# NTU-2019-ComputerNetwork
一個期末報告／以 Python 實作的、基於密碼學的信件傳輸協定／點對點加密

### Introduction

- 這是 NTU 2019 計算機網路的期末報告範例，以 Python 實作。
- 具體來說的話，是一個多個 clients 透過連上 server，互相傳送訊息的簡單軟體。
- 經過各種拓增，實作了一個簡單的基於 DHE 的公鑰系統，在這之上完成了完全的點對點加密協定，

### Use

- 執行前，需要在 pwd 下新增三個資料夾，並取名為 download, log, users。
- 打開 server，進 server.py 裡找 server 的 listen port，然後打開 clients 連上該 port。
- 連上之後便可以在 client 端敲各種指令和 server 端進行互動。

### Command ( Simple )

- register, reg <username> <password>
  - 向伺服器註冊一個用戶

- login <username> <password>
  - 向伺服器發送登入

- send <username> <message>
  - 向某個使用者發送文字短訊

- sendfile <username> <filepath>
  - 向某個使用者傳送檔案。

- msg
  - 切換至收訊模式
  - 在此模式下，用 f, a, d, q 分別完成查看最新訊息、接受最新訊息、刪除最新訊息、以及切換回原模式

- 跳進伺服器的暫存檔裡，可以發現包含檔案在內的所有東西全都是保密的。

總之就是這樣子的一個專案
