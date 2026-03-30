import psutil
import time

def test_net():
    try:
        io1 = psutil.net_io_counters()
        time.sleep(1)
        io2 = psutil.net_io_counters()
        sent = (io2.bytes_sent - io1.bytes_sent) / (1024 * 1024)
        recv = (io2.bytes_recv - io1.bytes_recv) / (1024 * 1024)
        print(f"Network Check: Sent={sent:.2f} MB/s, Recv={recv:.2f} MB/s")
    except Exception as e:
        print(f"Network Error: {e}")

if __name__ == "__main__":
    test_net()
