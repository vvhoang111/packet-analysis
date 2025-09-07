#Part 03-01.pcap
- 3 bytes đầu của địa chỉ MAC đại diện cho các Vendor id.

![](images/2025-09-07-16-35-56.png)
- Chúng ta có thể thay đổi địa chỉ MAC thành các vendor khác nhau để có thể đánh lừa người khác.
- Tiếp theo là địa chỉ DHCP:
    - Dùng để phần cứng máy tính được câp đia chỉ ip,
    - Ban đầu địa chỉ của sourc là `0.0.0.0`, src đã gửi `dhcp request`đến địa chỉ broadcast `255.255.255.255` do cũng không biết dhcp server ở đâu. Đó gọi là DHCP discover
    
    ![](images/2025-09-07-16-31-57.png)
    -Có thể thông qua Host Name để xác nhận được thông tin cùng với địa chỉ MAC đã nói ở trên để điều tra:
    
    ![](images/2025-09-07-16-35-18.png)

- Tiếp theo là NBNS
    - Để dùng để phát hiện host-name của Window và MacOS
    - Khi nhìn vào hình dưới , ta thấy địa chỉ src vừa được cấp đã gửi gói tin broadcast đến sup-ip, và ta cũng có thể thấy thêm 1 cách nữa để thấy hostname của MacOS cũng như tương tự của window

    ![](images/2025-09-07-16-43-50.png)

- Tiếp theo là OS và Web browser
    - Malware hay 1 số tool, extension có thể thay đổi 1 số dòng thông tin (user-agent) mà ta muốn điều tra về os và browser.Trong bài này cũng chưa nhắc tới việc đó , chỉ có các thông tin thật được sinh ra chưa bị sửa đổi.
    -Cách để xem thông tin:
        1. Nhấn vào packet muốn chọn, chuột phải chọn `Follow` -> `TCP Stream`

# Workshop part 03 - 02 .pcap
