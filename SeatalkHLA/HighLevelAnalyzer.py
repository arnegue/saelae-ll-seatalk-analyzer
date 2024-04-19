# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
import sys
import inspect
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

nmea_seatalk_multiplexer_path = r'C:\Git\Privat_Git\nmea_seatalk_multiplexer'  # Bad "hack" to import external libraries. But according to salea that's the only way
nmea_seatalk_multiplexer_venv_path = nmea_seatalk_multiplexer_path + r"\venv\Lib\site-packages"

sys.path.append(nmea_seatalk_multiplexer_venv_path)
sys.path.append(nmea_seatalk_multiplexer_path)

from seatalk import seatalk

class SeatalkDatagram:
    def __init__(self):
        self.length = 0
        self.data_nibble = 0
        self.data_frames = []


def get_numeric_byte_value(byte) -> int:
    """
    Returns numeric value of given byte

    :param byte: byte to convert
    :return: numeric integer value
    """
    return int.from_bytes(byte, "big")


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        }
    }

    def __init__(self):
        self.current_datagram = None
        self.all_datagrams = seatalk.SeatalkDevice.get_datagram_map()
        print("Extracted", len(self.all_datagrams), "datagrams")

    def decode(self, frame: AnalyzerFrame):
        if frame.data["IsCommandByte"]:
            if self.current_datagram is not None:
                print("Didn't receive enough frames until new CommandByte arrived")
            self.current_datagram = SeatalkDatagram()
            byte_name = "CommandByte"
        elif self.current_datagram is None:
            print("No CommandByte was received. Skipping frame")
            return
        elif len(self.current_datagram.data_frames) == 1:  # If command byte was received (second frame)
            byte_name = "LengthAttributeByte"
            byte_value = get_numeric_byte_value(frame.data['data'])
            self.current_datagram.length = byte_value & 0x0F
            self.current_datagram.data_nibble = (byte_value & 0xF0) >> 4
            print(self.current_datagram.length)
        else:
            byte_name = "DataByte"
        new_frame = AnalyzerFrame(byte_name, frame.start_time, frame.end_time, {'input_type': frame.type, 'data': frame.data['data'][0]})

        self.current_datagram.data_frames.append(new_frame)  # Append new frame

        if len(self.current_datagram.data_frames) == self.current_datagram.length + 3:  # If last datagram was read
            command_id = self.current_datagram.data_frames[0].data['data']
            command_name = "<Unknown>"
            data = None
            if command_id in self.all_datagrams:  # Get Datagram-Name (if known)
                data_gram_instance = self.all_datagrams[command_id]()
                attr_data = self.current_datagram.data_nibble
                data_bytes = bytearray()
                for dataframe in self.current_datagram.data_frames[2:]:
                    data_bytes.append(dataframe.data['data'])
                data_gram_instance.process_datagram(first_half_byte=attr_data, data=data_bytes)
                command_name = data_gram_instance.__class__.__name__
                data = data_gram_instance.__dict__

            return_frame = AnalyzerFrame(command_name, self.current_datagram.data_frames[0].start_time, self.current_datagram.data_frames[-1].end_time, {'Data': str(data)})
            self.current_datagram = None  # Reset current_diagram
            return return_frame
