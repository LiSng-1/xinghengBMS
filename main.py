from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

class XinghengBMSAnalyzer(HighLevelAnalyzer):
    """
    星恒BMS一线通协议解码器
    协议版本：A1.3.3
    """

    def __init__(self):
        # 状态机
        self.state = 'IDLE'
        # 边沿跟踪
        self.last_time = None
        self.last_value = None
        # 帧接收变量
        self.frame_bytes = []
        self.current_byte = 0
        self.bit_count = 0
        self.expected_len = None
        self.frame_start_time = None

        # 时间阈值（秒）
        self.SYNC_LOW_THRESH = 0.010      # 10ms
        self.SYNC_HIGH_THRESH = 0.011     # 11ms
        self.BIT_THRESH = 0.001           # 1ms，小于此值为1，大于为0
        self.STOP_LOW_THRESH = 0.004       # 4ms，停止信号低电平

        # 解析结果缓存（用于输出）
        self.result_frames = []

    def decode(self, waveform):
        """
        waveform: 生成器，产生 (time, value) 对
        """
        for time, value in waveform:
            if self.last_value is None:
                # 第一个采样点
                self.last_value = value
                self.last_time = time
                continue

            # 检测边沿（电平变化）
            if value != self.last_value:
                duration = time - self.last_time
                # 处理刚刚结束的电平（last_value）
                self._handle_edge(self.last_value, duration, time)
                # 更新
                self.last_value = value
                self.last_time = time

        # 返回生成的帧（如果有）
        # 注意：HLA要求decode返回单个帧或None，但我们可以通过yield返回多个帧，
        # 或者累积在列表中，在适当的时候返回。这里我们使用列表累积，并在每次解码后返回None，
        # 但Saleae的HLA机制是每次调用decode返回一个帧或None。实际上，decode会被反复调用，
        # 每次传入新的采样点，我们需要在检测到完整帧时返回该帧，其他时候返回None。
        # 为了简化，我们在_handle_edge中检测到帧完成时立即返回该帧，但decode函数只能返回一个值。
        # 更好的做法是在_handle_edge中将完成的帧存入队列，然后在decode的循环结束后返回None，
        # 但这样会导致帧延迟输出。另一种方法是使用yield，但HLA不支持yield。
        # 通常的做法是：在_handle_edge中当一帧完成时，创建一个AnalyzerFrame并保存到self.result，
        # 然后在decode的末尾返回该帧（如果有），并清空。但注意decode会被反复调用，所以我们需要
        # 在每次调用时返回之前累积的帧（如果有）。但这里我们简单处理：在_handle_edge中直接调用
        # self.create_frame并返回，但decode函数需要返回该帧。由于decode是在循环中，我们可以
        # 在_handle_edge中设置一个标志，然后在循环末尾返回。但为了代码清晰，我们采用在_handle_edge
        # 中调用一个方法来创建帧并存储，然后在decode的末尾返回第一个存储的帧（如果有）。
        # 但注意，一次decode调用可能只处理一个边沿，所以最多产生一帧。所以我们可以这样。
        # 实际上，HLA的decode函数每次调用应当返回一个帧或None，并且每帧只返回一次。
        # 因此，我们在_handle_edge中如果完成一帧，就立即构造并返回，但decode需要捕获这个返回值。
        # 我们可以修改结构，让_handle_edge返回帧，然后在decode中返回。但为了简单，我们采用
        # 在_handle_edge中调用self.output_frame，并将帧添加到列表，然后在decode末尾返回列表中的第一个。
        # 但注意，如果一次decode调用中产生了多帧（比如连续多个边沿处理），我们需要返回多个帧？实际上
        # 一次decode调用只处理一个采样点，所以最多一个边沿，因此最多一帧。
        # 所以我们可以在_handle_edge中调用self.output_frame，然后设置一个标志，在decode末尾返回。
        # 实现如下：
        if self.result_frames:
            frame = self.result_frames.pop(0)
            return frame
        return None

    def _handle_edge(self, last_state, duration, current_time):
        """
        处理边沿事件
        last_state: 刚刚结束的电平（0或1）
        duration: 该电平持续的时间（秒）
        current_time: 当前边沿的时间（新电平开始的时间）
        """
        if last_state == 0:   # 上升沿（低电平结束）
            if self.state == 'IDLE':
                # 可能检测到同步信号的低部分
                if duration >= self.SYNC_LOW_THRESH:
                    self.state = 'SYNC_HIGH'
                    # 记录同步开始时间（可选）
                    # 这里不记录，因为帧开始我们准备用第一个位的下降沿
                # 否则忽略
            elif self.state == 'BITS':
                # 处理一个位的低电平部分
                # 首先检查是否可能是停止信号（低电平过长）
                if duration >= self.STOP_LOW_THRESH:
                    # 遇到停止信号，结束当前帧（如果存在）
                    if self.frame_bytes:
                        self._output_frame(current_time)   # 以当前时间作为结束
                    self._reset_frame()
                    self.state = 'IDLE'
                    return

                # 正常位判断
                bit = 1 if duration <= self.BIT_THRESH else 0
                # 收集位（LSB first）
                self.current_byte |= (bit << self.bit_count)
                self.bit_count += 1
                if self.bit_count == 8:
                    # 完成一个字节
                    self.frame_bytes.append(self.current_byte)
                    self.current_byte = 0
                    self.bit_count = 0

                    # 检查是否已知总长度
                    if self.expected_len is None and len(self.frame_bytes) >= 3:
                        # 前三个字节：ID, 版本, 数据长度
                        data_len = self.frame_bytes[2]
                        self.expected_len = data_len + 4   # ID+版本+len+数据+校验

                    # 如果达到预期长度，完成一帧
                    if self.expected_len is not None and len(self.frame_bytes) == self.expected_len:
                        self._output_frame(current_time)
                        self._reset_frame()
                        self.state = 'IDLE'

        elif last_state == 1:   # 下降沿（高电平结束）
            if self.state == 'SYNC_HIGH':
                # 同步信号的高部分结束
                if duration >= self.SYNC_HIGH_THRESH:
                    # 同步成功，准备接收数据位
                    self.state = 'BITS'
                    # 初始化帧变量，以当前时间作为帧开始
                    self._reset_frame()
                    self.frame_start_time = current_time
                else:
                    # 同步失败，回到IDLE
                    self.state = 'IDLE'
            elif self.state == 'BITS':
                # 在BITS状态，下降沿只是高电平结束，不需要处理，但可以忽略
                pass
            # IDLE状态忽略高电平

    def _reset_frame(self):
        """重置帧接收变量"""
        self.frame_bytes = []
        self.current_byte = 0
        self.bit_count = 0
        self.expected_len = None
        # frame_start_time 由外部设置

    def _output_frame(self, end_time):
        """
        根据已接收的字节构造并输出一帧
        """
        if not self.frame_bytes:
            return

        frame_data = self.frame_bytes
        frame_id = frame_data[0]

        # 计算校验和
        calc_sum = sum(frame_data[:-1]) & 0xFF
        recv_sum = frame_data[-1]
        checksum_valid = (calc_sum == recv_sum)

        # 解析协议版本
        version_byte = frame_data[1]
        major = (version_byte >> 4) & 0x0F
        minor = version_byte & 0x0F
        version_str = f"{major}.{minor}"

        # 根据ID解析具体内容
        decoded = {}
        if frame_id == 0x01 and len(frame_data) == 20:   # 公有报文
            decoded = self._decode_public(frame_data)
        elif frame_id == 0x3A and len(frame_data) >= 4:  # 私有报文（实时信息）
            decoded = self._decode_private_3A(frame_data)
        elif frame_id == 0x3B and len(frame_data) >= 4:  # 私有报文（单串电压）
            decoded = self._decode_private_3B(frame_data)
        elif frame_id == 0x3C and len(frame_data) >= 4:  # 私有报文（电池唯一编码）
            decoded = self._decode_private_3C(frame_data)
        else:
            # 未知ID，仅输出原始字节
            decoded = {
                'raw_bytes': ' '.join([f'{b:02X}' for b in frame_data])
            }

        # 构造输出帧
        data = {
            'id': f'0x{frame_id:02X}',
            'version': version_str,
            'length': len(frame_data),
            'checksum_valid': checksum_valid,
            'decoded': decoded
        }

        # 帧起始时间：同步信号后的第一个下降沿，如果没有记录，使用当前时间减去大致长度
        start_time = self.frame_start_time if self.frame_start_time else (end_time - len(frame_data)*0.002)
        frame = AnalyzerFrame('bms_frame', start_time, end_time, data)
        self.result_frames.append(frame)

    # ---------- 具体报文解析函数 ----------
    def _decode_public(self, data):
        """公有报文 (ID=0x01) 解析"""
        # 索引参考表A.2
        return {
            'manufacturer': data[2],   # 电池厂商代码
            'model': data[3],           # 电池型号
            'cell_material': self._get_material_str(data[4]),
            'rated_voltage': (data[5] | (data[6] << 8)) * 0.1,   # V
            'rated_capacity': (data[7] | (data[8] << 8)) * 0.1,  # Ah
            'remaining_soc': data[9] * 0.5,                       # %
            'voltage': (data[10] | (data[11] << 8)) * 0.1,        # V
            'current': ((data[12] | (data[13] << 8)) * 0.1) - 500, # A
            'max_temp': data[14] - 40,                             # °C
            'min_temp': data[15] - 40,
            'mos_temp': data[16] - 40,
            'fault_code': data[17],
            'fault_desc': self._get_fault_desc(data[17]),
            'work_state': self._get_work_state(data[18]),
        }

    def _decode_private_3A(self, data):
        """私有报文 实时信息 (ID=0x3A) 解析，依据表A.5"""
        if len(data) < 4:
            return {}
        data_len = data[2]
        # 确保长度足够
        if len(data) < data_len + 4:
            return {'error': 'incomplete data'}

        # 提取字段
        soc = data[3] * 0.5
        voltage = (data[4] | (data[5] << 8)) * 0.1
        current = ((data[6] | (data[7] << 8)) * 0.1) - 500
        max_temp = data[8] - 40
        min_temp = data[9] - 40
        mos_temp = data[10] - 40
        fault = data[11]
        work_state_byte = data[12]
        bms_state_byte = data[13]

        return {
            'soc': soc,
            'voltage': voltage,
            'current': current,
            'max_temp': max_temp,
            'min_temp': min_temp,
            'mos_temp': mos_temp,
            'fault_code': fault,
            'fault_desc': self._get_fault_desc(fault),
            'work_state': self._get_work_state(work_state_byte),
            'bms_state': self._get_bms_state(bms_state_byte),
        }

    def _decode_private_3B(self, data):
        """私有报文 单串电压 (ID=0x3B) 解析，依据表A.6"""
        data_len = data[2]
        if len(data) < data_len + 4 or data_len % 2 != 0:
            return {'error': 'invalid length'}
        cell_count = data_len // 2
        cell_voltages = []
        for i in range(cell_count):
            low = data[3 + i*2]
            high = data[4 + i*2]
            raw = (low | (high << 8))
            if raw != 0xFFFF:
                cell_voltages.append(raw * 0.001)   # 单位mV? 文档写单位V? 但范围0-60000，精度1，可能是mV？实际文档写单位V，但精度1，范围0-60000，不合理。推测应为mV。按mV解析。
            else:
                cell_voltages.append(None)
        return {'cell_voltages_mV': cell_voltages}

    def _decode_private_3C(self, data):
        """私有报文 电池唯一编码 (ID=0x3C) 解析，依据表A.7"""
        data_len = data[2]
        if len(data) < data_len + 4:
            return {'error': 'incomplete data'}
        # 条码序号每个字节是ASCII码
        ascii_bytes = data[3:3+data_len]
        try:
            barcode = bytes(ascii_bytes).decode('ascii')
        except:
            barcode = ' '.join([f'{b:02X}' for b in ascii_bytes])
        return {'barcode': barcode}

    # ---------- 辅助函数 ----------
    def _get_material_str(self, code):
        materials = {
            0x00: '保留',
            0x01: '磷酸铁锂',
            0x02: '锰酸锂',
            0x03: '三元锂',
            0x04: '钴酸锂',
            0x05: '聚合锂',
            0x06: '钛酸锂',
            0x07: '铅酸',
            0x08: '镍氢',
            0x09: '钠',
        }
        return materials.get(code, f'未知({code})')

    def _get_fault_desc(self, code):
        """表A.4 故障类型"""
        faults = {
            0x00: '无故障',
            0x01: '放电过流二级保护',
            0x02: '放电过流一级保护',
            0x03: '低温充电保护',
            0x04: '充电高温保护',
            0x05: '放电高温保护',
            0x06: '欠压保护',
            0x07: '过压保护',
            0x08: '充电过流保护',
            0x09: '放电低温保护',
            0x0A: '充电MOS故障',
            0x0B: '放电MOS故障',
        }
        # 报警和预警未单独列，但故障码本身已区分
        return faults.get(code, f'未知({code})')

    def _get_work_state(self, byte_val):
        """电池工作状态 (bit0-2: 状态; bit5-7: 请求应答设备)"""
        state_map = {
            0: '电池单独放电',
            1: '电池单独充电',
            2: '电池单独回馈',
        }
        state = byte_val & 0x07
        req = (byte_val >> 5) & 0x07
        req_map = {
            0: '不需要应答',
            1: '充电器应答',
            2: 'ECU应答',
            3: 'TBOX应答',
        }
        return {
            'mode': state_map.get(state, f'未知({state})'),
            'request': req_map.get(req, f'预留({req})')
        }

    def _get_bms_state(self, byte_val):
        """BMS当前状态 (bit0:充电允许, bit1:充电器不合法上报)"""
        charge_enable = bool(byte_val & 0x01)
        charger_invalid = bool((byte_val >> 1) & 0x01)
        # 其他位预留
        return {
            'charge_enabled': charge_enable,
            'charger_invalid_reported': charger_invalid
        }

# 导出分析器
analyzer = XinghengBMSAnalyzer
