#include "GetSystemInfo.h"
#include "publicfun.h"


namespace SystemInfo
{
#ifdef WIN32
#include <iphlpapi.h>
#pragma comment(lib,"Iphlpapi.lib") 

bool getAdapterState(DWORD index)
{
	MIB_IFROW Info;
	memset(&Info, 0, sizeof(MIB_IFROW));
	Info.dwIndex = index;
	if (GetIfEntry(&Info) != NOERROR)
	{
		printf("ErrorCode = %d\n", GetLastError());
		return false;
	}
	if (Info.dwOperStatus == IF_OPER_STATUS_NON_OPERATIONAL
		|| Info.dwOperStatus == IF_OPER_STATUS_UNREACHABLE
		|| Info.dwOperStatus == IF_OPER_STATUS_DISCONNECTED

		|| Info.dwOperStatus == IF_OPER_STATUS_CONNECTING)
		return false;
	else if (Info.dwOperStatus == IF_OPER_STATUS_OPERATIONAL

		|| Info.dwOperStatus == IF_OPER_STATUS_CONNECTED)
		return true;
}

std::string GetMACaddress(void)
{
    IP_ADAPTER_INFO AdapterInfo[16]; // Allocate information for up to 16 NICs
    DWORD dwBufLen = sizeof(AdapterInfo); // Save the memory size of buffer


    DWORD dwStatus = GetAdaptersInfo( // Call GetAdapterInfo
        AdapterInfo, // [out] buffer to receive data
        &dwBufLen); // [in] size of receive data buffer

    bool bConnect = false;
    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
    std::string outMsg = "";
    do {
        bConnect = getAdapterState(pAdapterInfo->Index); 
        char acMAC[32];
        if ((pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET || pAdapterInfo->Type == 71) /*&&
             strstr(pAdapterInfo->Description, "VMware") == 0*/ &&
             bConnect)
        {
            //pAdapterInfoEnum->Description
            //pAdapterInfoEnum->AdapterName
            //pAdapterInfoEnum->Address

            sprintf_s(acMAC, "%02X-%02X-%02X-%02X-%02X-%02X",
                int(pAdapterInfo->Address[0]),
                int(pAdapterInfo->Address[1]),
                int(pAdapterInfo->Address[2]),
                int(pAdapterInfo->Address[3]),
                int(pAdapterInfo->Address[4]),
                int(pAdapterInfo->Address[5]));
            outMsg.append(acMAC);
            outMsg.append(",");
            outMsg.append(pAdapterInfo->IpAddressList.IpAddress.String);
            break;

        }
        //		std::string sDescript = pAdapterInfo->Description;

        pAdapterInfo = pAdapterInfo->Next; // Progress through linked list
    } while (pAdapterInfo);
    /*	if (outMsg.length() > 5){
    outMsg = outMsg.substr(0, outMsg.length() - 1);
    }
    */
    return outMsg;
}
#else
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define _PATH_PROCNET_DEV "/proc/net/dev"

void get_mac(char * mac_a, const char* ifrname)
{
    int                 sockfd;
    struct ifreq        ifr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        return;
    }
    strcpy(ifr.ifr_name, ifrname);      //Interface name

    if ((ioctl(sockfd, SIOCGIFHWADDR, &ifr)) == 0)
    {  //SIOCGIFHWADDR 获取hardware address
       //memcpy(mac_a, ifr.ifr_hwaddr.sa_data, 6);

        for (int i = 0; i < 6; ++i)
        {
            if (i != 5)
                sprintf(mac_a + 3 * i, "%02x-", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
            else
                sprintf(mac_a + 3 * i, "%02x", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
        }

    }
    return;
}

void GetIpAndMac(std::string& ip, std::string& mac)
{
    std::map<std::string,std::string> m_ipinfos;

    std::string strip = "";
    std::string strmac = "";

    struct ifaddrs * ifAddrStruct=NULL;
    void * tmpAddrPtr=NULL;

    //获取所有的ip
    getifaddrs(&ifAddrStruct);
    while (ifAddrStruct!=NULL)
    {
        if (ifAddrStruct->ifa_addr != NULL && ifAddrStruct->ifa_addr->sa_family==AF_INET)
        { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);

            if(ifAddrStruct->ifa_name == NULL && ifAddrStruct->ifa_name[0] == '\0')
            {
                ifAddrStruct=ifAddrStruct->ifa_next;
                continue;
            }

            if(strcmp(ifAddrStruct->ifa_name,"lo") == 0)
            {
                ifAddrStruct=ifAddrStruct->ifa_next;
                continue;
            }

            map<string,string>::iterator itr = m_ipinfos.find(ifAddrStruct->ifa_name);
            if(itr == m_ipinfos.end())
            {
                m_ipinfos.insert(make_pair(ifAddrStruct->ifa_name,addressBuffer));
            }

        }

        ifAddrStruct=ifAddrStruct->ifa_next;
    }

    char this_mac[64] = {0};
    std::map<std::string,std::string>::iterator itr = m_ipinfos.begin();
    for(;itr != m_ipinfos.end();itr++)
    {
        memset(this_mac,0,64);
        get_mac(this_mac,itr->first.c_str());
        if(this_mac[0] == '\0')
            continue;

        mac = this_mac;
        ip = itr->second;

        if(strcmp(itr->first.c_str(),"eth0") == 0)
        {
            break;
        }
    }

    //获取不到ip，用命令获取ip和mac
    if(ip.empty())
    {
        char buf[1024] = {0};
        FILE* fp = popen("hostname -I", "r");
        if(fp != NULL)
        {
            if(fgets(buf, 1023, fp) != NULL)
            {
                std::string tmpip(buf);
                int p = tmpip.find_first_of(" ");
                if(p != std::string::npos)
                {
                    ip = tmpip.substr(0,p);
                    strip = ip;
                }

            }

            pclose(fp);
            fp = NULL;
        }
    }

    if(mac.empty())
    {
        char buf[1024] = {0};
        FILE* fp = popen("ifconfig -a | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'", "r");
        if(fp != NULL)
        {
            std::string tmpmac = "";
            if(fgets(buf, 1023, fp) != NULL)
            {
                std::string tmpbuf(buf);
                tmpmac += tmpbuf;
                //printf("buf:%s\n",buf);

                int p = tmpmac.find_first_of("\n");
                if(p != std::string::npos)
                {
                    tmpmac = tmpmac.substr(0,p);

                    const char* pmac = Replace(tmpmac.c_str(),":","-");
                    mac = pmac;
                    strmac = mac;

                    if(pmac != NULL)
                    {
                        delete[] pmac;
                        pmac = NULL;
                    }
                }

            }

            pclose(fp);
            fp = NULL;

        }

    }

    if(mac.empty())
    {
        FILE* fp = fopen(_PATH_PROCNET_DEV,"r");
        if(fp == NULL)
            return;

        char buf[512] = {0};
        fgets(buf, sizeof buf, fp);
        fgets(buf, sizeof buf, fp);

        char this_mac[64] = {0};
        while (fgets(buf, sizeof buf, fp))
        {
            memset(this_mac,0,64);
            char *s, name[IFNAMSIZ];
            s = get_name(name, buf);
            get_mac(this_mac,name);

            if(this_mac[0] != '\0')
                break;
        }

        fclose(fp);
        fp = NULL;

        mac = this_mac;
    }

}

//使用ifconfig获取所有的mac
void GetVirtuallMac(std::map<std::string,int>& macvalues)
{
    char buf[1024] = {0};
    FILE* fp = popen("ifconfig -a | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'", "r");
    if(fp != NULL)
    {
        std::string tmpmac = "";
        while(fgets(buf, 1023, fp) != NULL)
        {
            std::string tmpbuf(buf);
            tmpmac += tmpbuf;

        }

        std::vector<std::string> onelues = SliteStr(tmpmac.c_str(),"\n");

        printf("[GetVirtuallMac]onelues:",onelues.size());
        for(int i = 0;i < onelues.size();i++)
        {
            if(strcmp(onelues[i].c_str(),"") == 0)
                continue;
            const char* pmac = Replace(onelues[i].c_str(),":","-");
            std::string mac = pmac;
            if(pmac != NULL)
            {
                delete[] pmac;
                pmac = NULL;
            }

            std::map<std::string,int>::iterator itr = macvalues.find(mac);
            if(itr == macvalues.end())
            {
                macvalues.insert(make_pair(mac,i));
                printf("%s,",mac.c_str());
            }
        }

        printf("\n");
        pclose(fp);
        fp = NULL;
    }

    if(macvalues.empty())
    {
        FILE* fh = fopen(_PATH_PROCNET_DEV,"r");
        if(fh == NULL)
            return;

        char buf[512] = {0};
        fgets(buf, sizeof buf, fh);
        fgets(buf, sizeof buf, fh);

        int i = 0;
        char this_mac[64] = {0};
        while (fgets(buf, sizeof buf, fh))
        {
            memset(this_mac,0,64);
            char *s, name[IFNAMSIZ];
            s = get_name(name, buf);
            get_mac(this_mac,name);

            std::map<std::string,int>::iterator itr = macvalues.find(this_mac);
            if(itr == macvalues.end())
            {
                macvalues.insert(make_pair(this_mac,i));
                i++;
            }

        }

        fclose(fh);
        fh = NULL;
    }



}

char *get_name(char *name, char *p)
{
    while (isspace(*p))
        p++;
    while (*p)
    {
        if (isspace(*p))
            break;
        if (*p == ':')
        { /* could be an alias */
            char *dot = p, *dotname = name;
            *name++ = *p++;
            while (isdigit(*p))
                *name++ = *p++;
            if (*p != ':')
            { /* it wasn't, backup */
                p = dot;
                name = dotname;
            }
            if (*p == '\0')
                return NULL;
            p++;
            break;
        }
        *name++ = *p++;
    }
    *name++ = '\0';
    return p;
}


#endif
}
