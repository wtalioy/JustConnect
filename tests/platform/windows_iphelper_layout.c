#include <winsock2.h>
#include <netioapi.h>
#include <stddef.h>
#include <stdio.h>

int main(void) {
    printf("{\"interface\":{\"size\":%zu,\"TransmitOffload\":%zu,\"ReceiveOffload\":%zu,\"DisableDefaultRoutes\":%zu},"
        "\"address\":{\"size\":%zu,\"DadState\":%zu,\"CreationTimeStamp\":%zu},"
        "\"route\":{\"size\":%zu,\"NextHop\":%zu,\"Metric\":%zu,\"Protocol\":%zu}}\n",
        sizeof(MIB_IPINTERFACE_ROW),offsetof(MIB_IPINTERFACE_ROW,TransmitOffload),offsetof(MIB_IPINTERFACE_ROW,ReceiveOffload),offsetof(MIB_IPINTERFACE_ROW,DisableDefaultRoutes),
        sizeof(MIB_UNICASTIPADDRESS_ROW),offsetof(MIB_UNICASTIPADDRESS_ROW,DadState),offsetof(MIB_UNICASTIPADDRESS_ROW,CreationTimeStamp),
        sizeof(MIB_IPFORWARD_ROW2),offsetof(MIB_IPFORWARD_ROW2,NextHop),offsetof(MIB_IPFORWARD_ROW2,Metric),offsetof(MIB_IPFORWARD_ROW2,Protocol));
    return 0;
}
