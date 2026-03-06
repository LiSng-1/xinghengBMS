from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting
import struct

# 星恒一线通协议时序定义（A1.3.3）
SYNC_T1_MIN = 10  # 同步信号T1 ≥10ms
SYNC_T2 = 1       # 同步信号T2=1ms
BIT_CYCLE = 2     # 位周期2ms
STOP_T1 = 5       # 停止信号T1=5ms
STOP_T2_MIN = 50  # 停止信号T2≥50ms

# 报文ID定义
PUB_MSG_ID = 0x01        # 公有报文
SINGLE_VOLT_MSG_ID = 0x3B# 单串电压报文
SN_MSG_ID = 0x3C         # 电池唯一码报文

# 电芯材料映射（表A.3）
CELL_MATERIAL = {
    0x00: "默认保留", 0x01: "磷酸铁锂", 0x02: "锰酸锂", 0x03: "三元锂",
    0x04: "钴酸锂",  0x05: "聚合锂",   0x06: "钛酸锂", 0x07: "铅酸",
    0x08: "镍氢",    0x09: "钠",      0x0A: "保留",   0xFF: "无效"
}

# 电池工作状态映射（表A.2）
BAT_WORK_STATE = {
    0x00: "单独放电", 0x01: "单独充电", 0x02: "单独回馈",
    0x03: "预留", 0xFF: "无效"
}

# 故障码/预警/报警映射（表A.4）
FAULT_CODE = {
    0x00: "无故障", 0x01: "放电过流二级保护", 0x02: "放电过流一级保护",
    0x03: "低温充电保护", 0x04: "充电高温保护", 0x05: "放电高温保护",
    0x06: "欠压保护", 0x07: "过压保护", 0x08: "充电过流保护",
    0x09: "放电低温保护", 0x0A: "充电MOS故障", 0x0B: "放电MOS故障",
    0xFF: "无效"
}
WARNING_CODE = {
    0x20: "预留", 0x21: "预留", 0x22: "放电过流一级预警",
    0x23: "低温充电预警", 0x24: "充电高温预警", 0x25: "放电高温预警",
    0x26: "欠压预警", 0x27: "过压预警", 0x28: "充电过流预警",
    0x29: "放电低温预警", 0xFF: "无效"
}
ALARM_CODE = {
    0x10: "预留", 0x11: "预留", 0x14: "充电高温异常报警",
    0x15: "放电高温异常报警", 0xFF: "无效"
}

# 充电状态映射（表A.5）
CHARGE_STATE = {
    0x00: "默认保留", 0x01: "满充停止", 0x02: "非法充电",
    0x03: "电池保护(可续充)", 0x04: "正在充电", 0xFF: "无效"
}

class StarHengBMSAnalyzer(HighLevelAnalyzer):
    """星恒BMS一线通协议高层解析器"""
    # 配置Saleae通道选择
    channels = {
        'bms_bus': {'type': 'digital', 'label': 'BMS一线通总线'}
    }

    def __init__(self):
        # 状态机变量
        self.state = 'IDLE'  # IDLE/SYNC_DETECT/BIT_READ/STOP_DETECT
        self.current_time = 0
        self.last_edge_time = 0
        self.edge_delta = 0
        # 帧数据缓存
        self.sync_buf = []
        self.bit_buf = []
        self.byte_buf = []
        self.frame_data = []
        # 解析结果缓存
        self.parsed_frames = []

    def calculate_delta(self, frame):
        """计算当前帧与上一帧的时间差(ms)"""
        self.current_time = frame.time.start
        if self.last_edge_time == 0:
            self.last_edge_time = self.current_time
            return 0
        delta = (self.current_time - self.last_edge_time).total_seconds() * 1000
        self.last_edge_time = self.current_time
        return round(delta, 1)

    def detect_sync(self, delta):
        """检测同步信号（T1≥10ms, T2=1ms）"""
        if len(self.sync_buf) < 2:
            self.sync_buf.append(delta)
            return False
        t1, t2 = self.sync_buf
        self.sync_buf = []
        return t1 >= SYNC_T1_MIN and abs(t2 - SYNC_T2) <= 0.5

    def read_bit(self, delta):
        """读取单个位（周期2ms，T1=0.5ms=1, T1=1.5ms=0）"""
        if abs(delta - BIT_CYCLE) > 0.5:
            return None
        t1 = delta / 2
        if abs(t1 - 0.5) <= 0.25:
            return 1
        elif abs(t1 - 1.5) <= 0.25:
            return 0
        return None

    def detect_stop(self, delta):
        """检测停止信号（T1=5ms, T2≥50ms）"""
        if len(self.sync_buf) < 2:
            self.sync_buf.append(delta)
            return False
        t1, t2 = self.sync_buf
        self.sync_buf = []
        return abs(t1 - STOP_T1) <= 0.5 and t2 >= STOP_T2_MIN

    def bit2byte(self):
        """位缓存转字节（小端：先传LSB）"""
        if len(self.bit_buf) < 8:
            return None
        byte = 0
        for i in range(8):
            byte |= (self.bit_buf[i] << i)
        self.bit_buf = self.bit_buf[8:]
        return byte

    def calc_checksum(self, data):
        """计算校验码：所有字节之和的低8位（协议定义）"""
        return sum(data) & 0xFF

    def parse_pub_msg(self, data):
        """解析公有报文（0x01，固定20字节，表A.2）"""
        if len(data) != 20:
            return {"错误": "公有报文长度错误，要求20字节"}
        # 按协议解析各字段（小端模式，物理值=传输值*精度+偏移量）
        pub_data = {
            "报文ID": hex(data[0]),
            "协议版本": f"主版本0x{(data[1]&0xF0)>>4}, 次版本0x{data[1]&0x0F}",
            "电池厂商代码": "星恒(0x01)" if data[2]==0x01 else f"无效(0x{data[2]:02X})",
            "电池型号": f"0x{data[3]:02X}" if data[3]!=0xFF else "无效",
            "电芯材料": CELL_MATERIAL.get(data[4], "保留"),
            "额定电压(V)": round(struct.unpack('<H', bytes(data[5:7]))[0]*0.1,1) if data[5:7]!=[0xFF,0xFF] else "无效",
            "额定容量(AH)": round(struct.unpack('<H', bytes(data[7:9]))[0]*0.1,1) if data[7:9]!=[0xFF,0xFF] else "无效",
            "剩余电量(%)": round(data[9]*0.5,1) if data[9]!=0xFF else "无效",
            "当前电压(V)": round(struct.unpack('<H', bytes(data[10:12]))[0]*0.1,1) if data[10:12]!=[0xFF,0xFF] else "无效",
            "当前电流(A)": round((struct.unpack('<H', bytes(data[12:14]))[0]-500)*0.1,1) if data[12:14]!=[0xFF,0xFF] else "无效",
            "最高温度(℃)": data[14]-40 if data[14]!=0xFF else "无效",
            "最低温度(℃)": data[15]-40 if data[15]!=0xFF else "无效",
            "MOS温度(℃)": data[16]-40 if data[16]!=0xFF else "无效",
            "电池故障": FAULT_CODE.get(data[17], "预留"),
            "工作状态": BAT_WORK_STATE.get(data[18], "预留"),
            "校验码": f"0x{data[19]:02X}(计算值:0x{self.calc_checksum(data[:19]):02X})",
            "校验结果": "通过" if data[19]==self.calc_checksum(data[:19]) else "失败"
        }
        return pub_data

    def parse_single_volt_msg(self, data):
        """解析单串电压报文（0x3B，表A.6）"""
        if len(data) < 4:
            return {"错误": "单串电压报文长度过短"}
        msg_id = data[0]
        proto_ver = data[1]
        data_len = data[2]
        checksum = data[-1]
        volt_data = data[3:-1]
        # 校验长度和校验码
        if len(volt_data) != data_len or checksum != self.calc_checksum(data[:-1]):
            return {"错误": "长度不匹配/校验码失败"}
        # 解析每串电压（16bit/串，mV）
        volts = []
        for i in range(0, len(volt_data), 2):
            if i+1 >= len(volt_data):
                break
            v = struct.unpack('<H', bytes(volt_data[i:i+2]))[0]
            volts.append(f"第{(i//2)+1}串: {v}mV" if v!=0xFFFF else f"第{(i//2)+1}串: 无效")
        return {
            "报文ID": hex(msg_id),
            "协议版本": f"0x{proto_ver:02X}",
            "数据长度": data_len,
            "单串电压": volts,
            "校验码": f"0x{checksum:02X}",
            "校验结果": "通过" if checksum == self.calc_checksum(data[:-1]) else "失败"
        }

    def parse_sn_msg(self, data):
        """解析电池唯一码报文（0x3C，表A.7，ASCII码）"""
        if len(data) < 4:
            return {"错误": "电池唯一码报文长度过短"}
        msg_id = data[0]
        proto_ver = data[1]
        data_len = data[2]
        checksum = data[-1]
        sn_data = data[3:-1]
        if len(sn_data) != data_len or checksum != self.calc_checksum(data[:-1]):
            return {"错误": "长度不匹配/校验码失败"}
        # 转换ASCII码
        sn = ''.join([chr(b) for b in sn_data if b!=0xFF and b!=0x00])
        return {
            "报文ID": hex(msg_id),
            "协议版本": f"0x{proto_ver:02X}",
            "数据长度": data_len,
            "电池唯一码": sn if sn else "无效",
            "校验码": f"0x{checksum:02X}",
            "校验结果": "通过" if checksum == self.calc_checksum(data[:-1]) else "失败"
        }

    def parse_frame(self, frame_data):
        """根据报文ID分发解析"""
        if len(frame_data) == 0:
            return {"错误": "空帧"}
        msg_id = frame_data[0]
        if msg_id == PUB_MSG_ID:
            return self.parse_pub_msg(frame_data)
        elif msg_id == SINGLE_VOLT_MSG_ID:
            return self.parse_single_volt_msg(frame_data)
        elif msg_id == SN_MSG_ID:
            return self.parse_sn_msg(frame_data)
        else:
            return {"报文ID": hex(msg_id), "类型": "私有报文(主机厂自定义)", "原始数据": [hex(b) for b in frame_data]}

    def process_frame(self, frame):
        """状态机处理每一个物理帧"""
        delta = self.calculate_delta(frame)
        if delta == 0:
            return None

        # 状态机：IDLE → 同步检测 → 位读取 → 停止检测 → 帧解析
        if self.state == 'IDLE':
            if self.detect_sync(delta):
                self.state = 'BIT_READ'
                self.frame_data = []
                return AnalyzerFrame("同步信号", frame.time, frame.time, {"状态": "同步信号检测成功"})
        elif self.state == 'BIT_READ':
            # 检测停止信号，优先于位读取
            if self.detect_stop(delta):
                self.state = 'IDLE'
                # 剩余位转字节
                while len(self.bit_buf)>=8:
                    b = self.bit2byte()
                    self.frame_data.append(b)
                # 解析帧
                parsed = self.parse_frame(self.frame_data)
                return AnalyzerFrame("协议帧", frame.time, frame.time, parsed)
            # 读取位并转字节
            bit = self.read_bit(delta)
            if bit is not None:
                self.bit_buf.append(bit)
                while len(self.bit_buf)>=8:
                    b = self.bit2byte()
                    self.frame_data.append(b)
        return None

    def analyze(self, frame):
        """Saleae核心回调：处理每一个输入帧"""
        result = self.process_frame(frame)
        if result is not None:
            return result
        return None

    def reset(self):
        """重置解析器状态"""
        self.state = 'IDLE'
        self.last_edge_time = 0
        self.sync_buf = []
        self.bit_buf = []
        self.byte_buf = []
        self.frame_data = []
