'''
------------------------------------------------------------------------------------------------------------------------
服务端的程序除了使用套接字的通信之外，还要使用多线程的方式来与多个客户端保持通信连接。
因此，服务端的基本流程如图。
当每次建立起一个新的连接时，就创建一个新的线程，向新的线程中传入该客户端套接字的信息，并保持通信.

在图形用户界面中，对于界面控件的操作最好在主线程中进行，以避免线程安全问题。
在使用 PyQt 或其他 GUI 框架时，所有的 GUI 操作通常都应该在主线程中执行。
如果在主线程之外进行耗时的操作，可能会导致界面假死或变得不响应，因为主线程被阻塞了。
在网络通信应用中，如果直接在主线程中执行 socket 操作，可能会导致界面冻结，用户无法与应用进行交互。
因此，将 socket 通信操作放在单独的线程中是一种常见的做法，以确保网络通信不会阻塞主线程。

所以需要创建 ServerThread 和 ClientThread 类继承自 QThread
目的就是为了在这两个线程中执行与网络通信相关的操作，而不影响主线程的正常运行。
这样，可以在这两个线程中监听连接、接收消息等，而主线程则可以继续响应用户的界面操作。

要注意的是，在 PyQt 中，界面元素（例如按钮、文本框等）通常只能在主线程中创建和修改。
如果需要在工作线程中更新界面元素，可以使用信号和槽机制，将工作线程中的信号连接到主线程的槽函数中，以实现跨线程更新界面。
------------------------------------------------------------------------------------------------------------------------
'''

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import socket
import sys

class MainWin(QMainWindow):
    def __init__(self, parent=None):
        super(MainWin, self).__init__(parent)
        self.pc = None                                  # 实例变量，存储一个客户端或服务器的实例
        self.MainSet()
        self.init_ui()

    def MainSet(self):
        self.setWindowTitle("ChatRoom")
        self.setFixedSize(600, 400)

    def init_ui(self):

        # 创建控件
        self.centerWidget = QWidget()                           # 中心窗口控件
        self.chatEdit = QTextEdit()                             # 聊天框
        self.inputLine = QLineEdit()                            # 输入框
        self.sendBtn = QPushButton("Send")                      # 消息发送按钮
        self.sendBtn.clicked.connect(self.sendInfo)             # 连接到sendInfo方法
        self.clearBtn = QPushButton("Clear")                    # 清空消息按钮
        self.clearBtn.clicked.connect(lambda: self.inputLine.clear())
        self.ConfigBox = QGroupBox("Config Box")                # 标题为Config Box的组合框容器控件
        self.ContralBox = QGroupBox("Control Box")              # 标题为Control Box的组合框容器控件
        self.ipEdit = QLineEdit()                               # IP输入栏
        self.portEdit = QLineEdit()                             # 端口输入栏
        self.hostEdit = QLineEdit()                             # 主机名输入栏
        self.serverRbtn = QRadioButton("Server")                # 选择为服务器
        self.serverRbtn.toggled.connect(self.radiobtnChange)    # 连接单选按钮信号与切换方法
        self.clientRbtn = QRadioButton("Client")                # 选择为客户端
        self.clientRbtn.toggled.connect(self.radiobtnChange)    # 连接单选按钮信号与切换方法
        self.connectBtn = QPushButton("连接服务器")               # 连接服务器按钮
        self.connectBtn.clicked.connect(self.setClient)         # 连接到setClient方法
        self.buildServerBtn = QPushButton("建立服务器")           # 建立服务器按钮
        self.buildServerBtn.clicked.connect(self.setServer)     # 连接到setServer方法
        self.quitBtn = QPushButton("退出")                       # 退出按钮
        self.quitBtn.clicked.connect(self.quit)                 # 连接到quit方法
        self.statusBar = QStatusBar()                           # 状态栏

        # 创建布局
        self.mainLayout = QGridLayout()                 # 中心框的网格布局
        self.rightTopLayout = QGridLayout()             # 右上角的网格布局
        self.rightBottomLayout = QVBoxLayout()          # 右下角的垂直布局

        self.setCentralWidget(self.centerWidget)
        self.setStatusBar(self.statusBar)

        # 将控件添加到中心框布局中
        self.centerWidget.setLayout(self.mainLayout)
        self.mainLayout.addWidget(self.chatEdit, 0, 0, 6, 2)            # 聊天框控件的位置参数，所在行、所在列、所占行数、所占列数
        self.mainLayout.addWidget(self.inputLine, 6, 0, 1, 2)           # 输入框控件的位置参数
        self.mainLayout.addWidget(self.sendBtn, 7, 0, 1, 1)             # 消息发送按钮的位置参数
        self.mainLayout.addWidget(self.clearBtn, 7, 1, 1, 1)            # 清空消息按钮的位置参数
        self.mainLayout.addWidget(self.ConfigBox, 0, 2, 5, 1)           # Config Box组合框容器控件的位置参数
        self.mainLayout.addWidget(self.ContralBox, 5, 2, 3, 1)          # Control Box组合框容器控件的位置参数

        # 将控件添加到右上角的网格布局中
        self.ConfigBox.setLayout(self.rightTopLayout)
        self.rightTopLayout.addWidget(QLabel("Server IP"), 0, 0, 1, 4)      # 将Lable Server IP 添加到rightTopLayout
        self.rightTopLayout.addWidget(self.ipEdit, 0, 1, 1, 3)              # 将ipEdit添加到rightTopLayout
        self.rightTopLayout.addWidget(QLabel("Server Port"), 2, 0, 1, 1)    # 将Lable Server Port 添加到rightTopLayout
        self.rightTopLayout.addWidget(self.portEdit, 2, 1, 1, 3)            # 将portEdit添加到rightTopLayout
        self.rightTopLayout.addWidget(QLabel("Host Name"), 3, 0, 1, 1)      # 将Lable Host Name 添加到rightTopLayout
        self.rightTopLayout.addWidget(self.hostEdit, 3, 1, 1, 3)            # 将hostEdit添加到rightTopLayout
        self.rightTopLayout.addWidget(self.serverRbtn, 4, 0, 1, 2)          # 将serverRbtn添加到rightTopLayout
        self.rightTopLayout.addWidget(self.clientRbtn, 4, 2, 1, 2)          # 将clientRbtn添加到rightTopLayout

        # 将控件添加到右下角的垂直布局中
        self.ContralBox.setLayout(self.rightBottomLayout)
        self.rightBottomLayout.addWidget(self.connectBtn)                   # 将连接服务器按钮添加到 rightBottomLayout
        self.rightBottomLayout.addWidget(self.buildServerBtn)               # 将创建服务器按钮添加到 rightBottomLayout
        self.rightBottomLayout.addWidget(self.quitBtn)                      # 将退出按钮添加到 rightBottomLayout

    def radiobtnChange(self, status):
        if self.serverRbtn.isChecked():
            self.connectBtn.setEnabled(False)
            self.buildServerBtn.setEnabled(True)
        elif self.clientRbtn.isChecked():
            self.connectBtn.setEnabled(True)
            self.buildServerBtn.setEnabled(False)

    def setServer(self):
        host = self.hostEdit.text() or "服务管理员"
        port = int(self.portEdit.text() or 9999)
        ip = self.ipEdit.text() or "127.0.0.1"
        self.pc = Server(self, ip, host, port)

    def setClient(self):
        host = self.hostEdit.text() or "匿名用户"
        port = int(self.portEdit.text() or 9999)
        ip = self.ipEdit.text() or "127.0.0.1"
        self.pc = Client(self, ip, host, port)

    def sendInfo(self):
        if self.pc is None:
            self.statusBar.showMessage("send info field cause not connected!!")
        else:
            info = self.inputLine.text()
            if info:
                info = self.pc.hostName + ":\n" + info
                self.pc.btnsend(info)
            else:
                self.statusBar.showMessage("input can't be none!")

    def quit(self):
        if self.pc:
            self.pc.closeThread()
        self.close()

class Server():
    def __init__(self, widget, ip, host, port):
        self.widget = widget
        self.ip = ip
        self.hostName = host
        self.port = port
        self.serverDict = {}                    # 服务线程字典
        self.serverID = 0                       # 初始的服务线程id
        self.buildSocket()

    def buildSocket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # 参数AF_INET表示该socket在网络层使用IP协议; 参数SOCK_STREAM表示该socket传输层使用TCP协议
        self.socket.bind((self.ip, self.port))                              # 绑定端口与主机名
        self.socket.listen(10)                                              # 设定最大连接数
        self.buildServer()

    def buildServer(self):
        server = ServerThread(str(self.serverID), self.socket)          # 创建一个新的 ServerThread 对象，用于处理新的客户端连接。将 self.serverID 和服务器的套接字传递给线程对象。
        self.serverDict[str(self.serverID)] = server                    # 将新创建的 ServerThread 对象添加到服务器字典中，以便稍后管理和与特定客户端通信。
        self.serverID += 1                                              # 增加服务器的标识，以便为下一个连接创建唯一的标识符。

        # 将 ServerThread 对象的信号连接到 Server 类中的方法。这样，当线程中发生特定事件时，将调用相应的方法。
        server._flag.connect(self.getFlag)
        server._signal.connect(self.getMessage)
        server._text.connect(self.getText)
        server.start()

    def bordCastInfo(self, info):
        for client in self.serverDict:                              # 遍历服务器字典中的每个客户端。
            try:
                if self.serverDict[client].clientsocket:            # 检查当前客户端的 clientsocket 是否存在，确保客户端仍然处于连接状态。
                    self.serverDict[client].sendToClient(info)      # 将消息传入指定的客户端
            except Exception as reason:
                self.getFlag("@@@".join([client, "disconnect"]))    # 运行函数,停止某个客户端的监听(相当于关闭)
        print("广播成功")                                            # @@@ 用作分隔符，以便在 getFlag 方法中解析出客户端的标识符和断开连接的信息。

    def btnsend(self, text):
        self.widget.chatEdit.append(text)        # 将传入的消息 text 追加到服务端的图形用户界面（GUI）中的聊天框 (chatEdit) 中。
        self.bordCastInfo(text)                  # 调用 broadcast_message 方法，将消息广播给所有连接的客户端。

    def closeThread(self):
        for server in self.serverDict:           # 遍历 self.serverDict 中的所有线程，将它们的 runflag 设置为 False，以停止线程的运行。
            self.serverDict[server].runflag = False

    def getFlag(self, flag):
        flag = flag.split("@@@")
        if flag[1] == "connect":                 # 如果传来连接成功,则新开一个线程监听
            self.buildServer()
        elif flag[1] == "disconnect":            # 如果连接出现问题，则关闭相应的服务线程。
            self.serverDict[flag[0]].runflag = False

    def getMessage(self, signal):
        signal = signal.split("@@@")            # 当收到来自服务线程的消息时，该方法解析消息，更新服务端的状态栏（statusBar）以显示服务线程的状态信息。
        self.widget.statusBar.showMessage("serverID " + signal[0] + " status:" + signal[1])         # 消息中包含了服务线程的ID以及状态信息

    def getText(self, text):
        self.widget.chatEdit.append(text)        # 通过 broadcast_message 方法将消息广播给所有连接的客户端，以实现实时聊天。
        self.bordCastInfo(text)

class Client():
    def __init__(self, widget, ip, hostName, port):
        self.widget = widget
        self.ip = ip
        self.hostName = hostName
        self.port = port
        self.buildSocket()

    def buildSocket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # 创建套接字
        self.client = ClientThread(self.socket)                             # 将创建的套接字传递给该对象，获取连接
        self.client._flag.connect(self.getFlag)                             # 连接 ClientThread 对象的 _flag 信号到 getFlag 方法，当客户端线程发出连接状态标志时，将调用 getFlag 方法。
        self.client._signal.connect(self.getMessage)                        # 连接 ClientThread 对象的 _signal 信号到 getMessage 方法，调用 getMessage 方法。
        self.client._text.connect(self.getText)                             # 连接 ClientThread 对象的 _text 信号到 getText 方法。当客户端线程发出文本消息时，将调用 getText 方法。
        if self.client.connectServer(self.ip, self.port):                   # 尝试连接到指定的服务器 IP 和端口。
            self.client.start()

    def sendToServer(self, text):
        try:
            self.socket.send(text.encode('utf-8'))          # 通过套接字发送消息给服务器。消息在发送之前使用 UTF-8 编码。
        except Exception as reason:
            self.getMessage(reason)
            self.getFlag("disconnect")                      # 发送连接失败标志

    def btnsend(self, text):
        self.sendToServer(text)                             # 通过调用 send_message 方法，将指定的文本消息发送给服务器。

    def closeThread(self):
        self.runflag = False                                # 关闭线程

    def getFlag(self, flag):
        if flag == "connect":           # 处理连接状态标志。如果收到 "connect" 标志，显示连接成功的消息；
            self.widget.statusBar.showMessage("connect success!!")
        elif flag == "disconnect":      # 如果收到 "disconnect" 标志，将客户端线程的 runflag 设置为 False，从而关闭线程。
            self.client.runflag = False

    def getMessage(self, signal):
        self.widget.statusBar.showMessage(signal)       # 显示接收到的消息在状态栏中。

    def getText(self, text):
        self.widget.chatEdit.append(text)               # 将接收到的文本消息追加到聊天框中。

class ServerThread(QThread):
    _signal = pyqtSignal(str)       # 设定信号,主要向主线程发送信号
    _text = pyqtSignal(str)         # 设定信号,向主线程发送接收到的信息
    _flag = pyqtSignal(str)         # 设定信号,向主线程发送连接状态标志

    def __init__(self, serverID, serverSocket):
        super(ServerThread, self).__init__()
        self.serverID = serverID                        # 获得主机实例，存储服务器线程的标识符，用于标识不同的服务器线程。
        self.serverSocket = serverSocket                # 存储服务器的套接字，用于监听客户端的连接。
        self.clientsocket = None                        # 存储客户端套接字。在服务器接受客户端连接后，这个属性将被设置为实际的客户端套接字。
        self.addr = None                                # 存储客户端的地址信息。
        self.runflag = True                             # 控制线程的运行状态
        self.connectList = ["connect", "disconnect"]    # 定义连接状态的标志列表，连接成功与连接失败

    def run(self):
        self.sendMessage("Waiting for customer......")                      # 通知服务器正在等待客户端的连接。
        self.clientsocket, self.addr = self.serverSocket.accept()           # 收到客户端的连接后返回 连接控件,地址(持续监听,直到接收到执行下一个操作)
        self.sendText("Customer IP: %s" % str(self.addr) + " is linking!")  # 通知主线程客户端的连接信息。
        self.sendFlag(0)                                                    # 发送连接成功标志
        self.getMessage()

    def getMessage(self):
        while self.runflag:
            try:
                data = self.clientsocket.recv(1024).decode('utf-8')         # 从客户端的套接字 self.clientsocket 接收数据，最多接收 1024 字节，并使用 UTF-8 解码。
                self.sendText(data)                                         # 将接收到的消息通过信号发送给主线程，以更新界面显示。
            except Exception as reason:
                self.sendMessage(str(reason))
                self.sendText(str(self.addr) + " break connect...")         # 向主线程发送客户端断开连接的消息。
                self.sendFlag(1)                                            # 发送断开连接标志
                break
        self.clientsocket.close()                                           # 关闭客户端的套接字。
        print("线程关闭成功")

    def sendToClient(self, info):
        try:
            self.clientsocket.send(info.encode("utf-8"))                    # 将消息 info 编码成 UTF-8 格式并发送到客户端的套接字
            print("广播成功")
        except Exception as reason:
            print("广播失败原因", reason)
            self.sendMessage(self.addr + " break connect...")               # 向主线程发送客户端断开连接的消息。
            self.sendFlag(1)                                                # 向主线程发送断开连接的标志。

    def sendMessage(self, message):                                         # 通过 self._signal 信号发送消息给主线程。
        self._signal.emit("@@@".join([self.serverID, message]))             # 使用 @ 符号连接 serverID 和消息 message，形成一个以 @@@ 为分隔符的字符串，以便主线程能够解析并识别。

    def sendText(self, text):
        self._text.emit(text)                                               # 通过 self._text 信号发送接收到的文本消息给主线程。

    def sendFlag(self, flagIndex):                                                      # 通过 self._flag 信号发送连接状态标志给主线程。
        self._flag.emit("@@@".join([self.serverID, self.connectList[flagIndex]]))       # 使用 @ 符号连接 serverID 和连接状态列表中的标志

class ClientThread(QThread):
    _signal = pyqtSignal(str)       # 用于发送连接状态信息（连接成功或连接失败）给主线程。
    _text = pyqtSignal(str)         # 用于发送接收到的文本消息给主线程。
    _flag = pyqtSignal(str)         # 用于发送连接状态标志给主线程。

    def __init__(self, serverSocket):
        super(ClientThread, self).__init__()
        self.serverSocket = serverSocket                # 表示与服务器建立的套接字。
        self.runflag = True                             # 表示线程是否应该继续运行。
        self.connectList = ["connect", "disconnect"]    # 存储连接成功和连接失败的标志。

    def connectServer(self, ip, port):
        try:
            self.serverSocket.connect((ip, port))       # 接受服务器的 IP 地址和端口作为参数，然后尝试连接服务器。
            self.sendFlag(0)                            # 发送连接成功标志
            return True
        except Exception as reason:
            self.sendMessage(reason)
            self.sendFlag(1)                            # 发送链接失败标志
            return reason

    def run(self):
        while self.runflag:
            try:
                msg = self.serverSocket.recv(1024).decode("utf-8")      # 接受服务端消息
                self.sendText(msg)                                      # 成功接收到消息，则将消息发送给主线程，以便更新界面。
            except Exception as reason:
                self.sendMessage(reason)
                self.sendFlag(1)                                        # 发送连接失败标志
                break

    def sendMessage(self, message):
        self._signal.emit(str(message))

    def sendText(self, text):
        self._text.emit(str(text))

    def sendFlag(self, flagIndex):
        self._flag.emit(str(self.connectList[flagIndex]))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWin()
    win.show()
    sys.exit(app.exec_())
