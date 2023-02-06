/*!
 \file Debug.cpp
 \brief GDB connector
 \author Màrius Montón
 \date February 2021
 */
// SPDX-License-Identifier: GPL-3.0-or-later


#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <boost/algorithm/string.hpp>

#include "Debug.h"

namespace riscv_tlm {

    constexpr char nibble_to_hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    SC_HAS_PROCESS(Debug);
    Debug::Debug(riscv_tlm::CPURV32 *cpu, Memory *mem) :  default_time(10, sc_core::SC_NS),sc_module(sc_core::sc_module_name("Debug")) {
        dbg_cpu32 = cpu;
        dbg_cpu64 = nullptr;
        register_bank32 = nullptr;
        register_bank64 = nullptr;
        dbg_mem = mem;
        cpu_type = riscv_tlm::RV32;
        
        SC_THREAD(handle_gdb_loop);      
        
        SC_THREAD(gdb_continue_op_loop);                
          
    }

    Debug::Debug(riscv_tlm::CPURV64 *cpu, Memory *mem) : default_time(10, sc_core::SC_NS),sc_module(sc_core::sc_module_name("Debug")) {
        dbg_cpu32 = nullptr;
        dbg_cpu64 = cpu;
        register_bank32 = nullptr;
        register_bank64 = nullptr;
        dbg_mem = mem;
        cpu_type = riscv_tlm::RV64;
        
        SC_THREAD(handle_gdb_loop);

        SC_THREAD(gdb_continue_op_loop);                
    }

    Debug::~Debug() = default;

    void Debug::send_packet(int m_conn, const std::string &msg) {
        std::string frame = "+$" + msg + "#" + compute_checksum_string(msg);

        memcpy(iobuf, frame.c_str(), frame.size());

        ::send(m_conn, iobuf, frame.size(), 0);
    }

    std::string Debug::receive_packet() {
        ssize_t nbytes = ::recv(conn, iobuf, bufsize, 0);
        if (nbytes == -1) {
            return "";
        }
        else if (nbytes == 0) {
            return "";
        } else if (nbytes == 1) {
            return std::string{"+"};
        } else {
            char *start = strchr(iobuf, '$');
            char *end = strchr(iobuf, '#');            
            //printf("debug_loc %d %d %d\n",int(start-iobuf),int(end-iobuf),int(nbytes));
            if (end != NULL) {                
                std::string message(start + 1, end -(start + 1));
                return message;
            }
            else {                
                std::string message(start + 1, nbytes-1);
                return message;
            }            
        }
    }

    void Debug::parsing_load_cmd(std::string cmd_in) {
        char *start_addr = strchr(iobuf, 'X');
        char *end_addr0 = strchr(iobuf, ',');
        char *end_addr1 = strchr(iobuf, ':');
        char *end_addr2 = strchr(iobuf, '#');
        
        std::string src_addr(start_addr+1,end_addr0);
        std::string cp_size(end_addr0+1,end_addr1);
        
        uint32_t int_src_addr = stoi(src_addr,nullptr,16);
        uint32_t int_cp_size = stoi(cp_size,nullptr,16);
        //std::cout << "cmdInfo> " << src_addr << " " << std::hex << int_src_addr  << " "<< std::hex  << cp_size << " " << int_cp_size  << std::endl;
               
        auto special_cnt = 0;        
        if (int_cp_size > 0) {
            int start_idx = end_addr1-start_addr + 1;            
            std::string dat_out = cmd_in.substr(start_idx);                    
            //char *c = const_cast<char*>(dat_out.c_str());
            char *c = end_addr1+1;            
            auto specal_char = false;
            
            //for (auto i = 0; i < dat_out.length()-3;i++) {            
            auto i = 0u;
            while (1) {            
                uint8_t tmp0_int = uint8_t(c[i]);

                if (c[i++] == '#') {
                    break;
                }

                if (tmp0_int == 0x7d) {
                    special_cnt++;
                    specal_char = true;
                } 
                else {
                    if (specal_char) {
                        tmp0_int = 0x20 | tmp0_int;
                        specal_char = false;
                    }
                                       
                    if (cpu_type == riscv_tlm::RV32) {
                        dbg_cpu32->writeDataMem(int_src_addr++,tmp0_int,1);                        
                    }
                    else if (cpu_type == riscv_tlm::RV64) {
                        dbg_cpu64->writeDataMem(int_src_addr++,tmp0_int,1);                        
                    }
                    else {
                        std::cout << "Error in " << __FILE__ << " " << __LINE__ << std::endl;
                    }
                }                
            }            
        }
    }

    void Debug::do_wr_mem_cmd(std::string cmd_in) {
        char *start_addr = strchr(iobuf, 'M');
        char *end_addr0 = strchr(iobuf, ',');
        char *end_addr1 = strchr(iobuf, ':');
        
        std::string src_addr(start_addr+1,end_addr0);
        std::string cp_size(end_addr0+1,end_addr1);
        
        uint32_t int_src_addr = stoi(src_addr,nullptr,16);
        uint32_t int_cp_size = stoi(cp_size,nullptr,16);
        //std::cout << "cmdInfo> " << src_addr << " " << std::hex << int_src_addr  << " "<< std::hex  << cp_size << " " << int_cp_size  << std::endl;

        auto special_cnt = 0;
        std::string out_string = "";
        auto out_cnt = 0u;
        if (int_cp_size > 0) {
            std::string dat_out = cmd_in.substr(end_addr1-iobuf);            
            char *c = const_cast<char*>(dat_out.c_str());
            //std::cout << "cmd_data> " << dat_out << std::endl;
            auto specal_char = false;
            
            for (auto i = 0; i < dat_out.length();i++) {
                uint8_t tmp0_int = uint8_t(c[i+0]);                
                out_string += c[i+0];
                out_cnt++;

                if (out_cnt == 2) {
                    uint8_t tmp0_int = stoi(out_string,nullptr,16);
                    out_cnt = 0;
                    out_string = "";

                    if (cpu_type == riscv_tlm::RV32) {
                        dbg_cpu32->writeDataMem(int_src_addr++,tmp0_int,1);                        
                    }
                    else if (cpu_type == riscv_tlm::RV64) {
                        dbg_cpu64->writeDataMem(int_src_addr++,tmp0_int,1);                        
                    }
                    else {
                        std::cout << "Error in " << __FILE__ << " " << __LINE__ << std::endl;
                    }
                }
            }
        }
    }
    std::stringstream Debug::do_rd_mem_cmd(std::string cmd_in) {
        char *pEnd;
        long addr = strtol(cmd_in.c_str() + 1, &pEnd, 16);
        int len = strtol(pEnd + 1, &pEnd, 16);
        int residual_byte;
        uint32_t rd_dat;
        std::stringstream stream;
        uint8_t c_out;

        stream << std::setfill('0') << std::hex;
        residual_byte = 0;
        for (int i = 0; i < len;i++) {
            if (residual_byte == 0) {
                if (cpu_type == riscv_tlm::RV32) {
                    rd_dat = dbg_cpu32->readDataMem(addr,4);
                }
                else if (cpu_type == riscv_tlm::RV64) {
                    rd_dat = dbg_cpu64->readDataMem(addr,4);
                }
                else {
                    std::cout << "Error in " << __FILE__ << " " << __LINE__ << std::endl;
                }
                //std::cout << "mem_rd> " << std::hex << addr << " " << std::setfill('0') << std::setw(8) << rd_dat << std::endl;
                addr += 4;
                residual_byte = 4;
            }
            c_out = uint8_t(rd_dat & 0xFF);
            rd_dat = rd_dat >> 8;
            residual_byte--;
            stream << std::setw(2) << (0xFF & c_out);            
            //std::cout << "test_rd>" << std::setfill('0') << std::hex << std::setw(2) << (0xFF & c_out) << std::endl;
        }
        return stream;
    }

    uint32_t Debug::string_to_hex(std::string string_in) {
        char *c = const_cast<char*>(string_in.c_str());
        std::string out_string = "";
        for (auto i = 0; i < string_in.length()/2;i++) {
            out_string = c[2*i+1] + out_string;
            out_string = c[2*i] + out_string;
        }
        uint32_t tmp0_int = stoi(out_string,nullptr,16);
        return tmp0_int;
    }
    std::string Debug::int_to_string_byte_reverse(uint32_t dat_in) {

        std::ostringstream ss;
        
        ss << std::setw(8) << std::setfill('0') << std::hex << dat_in;
        auto tmp = ss.str();
        char *c = const_cast<char*>(tmp.c_str());
        std::string out_string = "";
        for (auto i = 0; i < tmp.length()/2;i++) {
            out_string = c[2*i+1] + out_string;
            out_string = c[2*i] + out_string;
        }
        return out_string;
    }

    void Debug::gdb_continue_op() {
        bool breakpoint_hit = false;
        bool watchpoint_hit = false;
        bool bkpt = false;
        bool whpt = false;
        do {
            std::uint64_t currentPC;

            if (cpu_type == riscv_tlm::RV32) {                                               
                std::tie(bkpt,whpt) = dbg_cpu32->CPU_step();                        
                currentPC = dbg_cpu32->getPC_rv32();
                
            } else {                        
                std::tie(bkpt,whpt) = dbg_cpu64->CPU_step();                        
                currentPC = dbg_cpu64->getPC_rv64();
            }
            sc_core::wait(default_time);

            auto search = breakpoints.find(currentPC);
            if (search != breakpoints.end()) {
                breakpoint_hit = true;
            }

            watchpoint_hit = find_watchpoint();
            //std::cout << "PC " << std::hex << currentPC << " " << watchpoint_hit << std::endl;

        } while ((breakpoint_hit == false) && (bkpt == false) && (watchpoint_hit == false) );

        // std::cout << "Breakpoint hit at 0x" << std::hex << register_bank->getPC() << std::endl;
        send_packet(conn, "S05"); //SIGTRAP
    }   
    
    void Debug::gdb_continue_op_loop() {        
        while (1) {
            wait(gdb_continue_e);
            gdb_continue_op();
        }
    }
    
    void Debug::gdb_step_op() {

        bool breakpoint;
        if (cpu_type == riscv_tlm::RV32) {
            dbg_cpu32->CPU_step();            
        } else {
            dbg_cpu64->CPU_step();            
        }
        sc_core::wait(default_time);

        std::uint64_t currentPC;
        if (cpu_type == riscv_tlm::RV32) {
            currentPC = dbg_cpu32->getPC_rv32();
            
        } else {
            currentPC = dbg_cpu64->getPC_rv64();
        }

        auto search = breakpoints.find(currentPC);
        if (search != breakpoints.end()) {
            breakpoint = true;
        } else {
            breakpoint = false;
        }     
        send_packet(conn, "S05"); //SIGTRAP
    }

    void Debug::insert_watchpoint(uint32_t cmd_type,std::string msg_in) {
        
        mem_watchpoint_t watchpoint;
        uint32_t kind ;
        uint32_t result;
        if (cmd_type == 2) {
            result = sscanf(msg_in.c_str(), "Z2,%x,%x\0", &watchpoint.mem_addr, &watchpoint.addr_length);            
            kind = 2;
        }
        else if (cmd_type == 3) {
            result = sscanf(msg_in.c_str(), "Z3,%x,%x\0", &watchpoint.mem_addr, &watchpoint.addr_length);            
            kind = 3;
        }
        else if (cmd_type == 4) {
            result = sscanf(msg_in.c_str(), "Z4,%x,%x\0", &watchpoint.mem_addr, &watchpoint.addr_length);            
            kind = 4;
        }
        else {
            kind = 0;
        }

        if (result != 2) {
            std::cout << "parsing packet cmd fail\n";
            send_packet(conn, "");
        }
                
        if (kind == 2) {
            auto rlt = mem_wr_watchpoints.insert(watchpoint);
            if (rlt.second == true) {
                //std::cout << "write watchpoint set to address " << watchpoint << std::endl;
                send_packet(conn, "OK");            
            }
            else {
                std::cout << "fail in write watchpoint set to address " << watchpoint << std::endl;
                send_packet(conn, "");      
            }
        }
        else if (kind == 3) {
            auto rlt = mem_rd_watchpoints.insert(watchpoint);
            if (rlt.second == true) {
                //std::cout << "read watchpoint set to address " << watchpoint << std::endl;
                send_packet(conn, "OK");            
            }
            else {
                std::cout << "fail in write watchpoint set to address " << watchpoint << std::endl;
                send_packet(conn, "");      
            }            
        }
        else if (kind == 4) {
            auto rlt = mem_wr_watchpoints.insert(watchpoint);
            mem_rd_watchpoints.insert(watchpoint);
            if (rlt.second == true) {
                //std::cout << "watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "OK");            
            }
            else {
                std::cout << "fail in write watchpoint set to address " << watchpoint << std::endl;
                send_packet(conn, "");      
            }                        
        }
        else {
            std::cout << "watchpoint fail0" <<  watchpoint << std::endl;
            send_packet(conn, "");
        }            
             
    }

    void Debug::delete_watchpoint(uint32_t cmd_type,std::string msg_in) {
        
        mem_watchpoint_t watchpoint;
        uint32_t kind ;
        uint32_t result;

        if (cmd_type == 2) {
            result = sscanf(msg_in.c_str(), "z2,%x,%x\0", &watchpoint.mem_addr, &watchpoint.addr_length);
            kind = 2;
        }
        else if (cmd_type == 3) {
            result = sscanf(msg_in.c_str(), "z3,%x,%x\0", &watchpoint.mem_addr, &watchpoint.addr_length);
            kind = 3;
        }
        else if (cmd_type == 4) {
            result = sscanf(msg_in.c_str(), "z4,%x,%x\0", &watchpoint.mem_addr, &watchpoint.addr_length);
            kind = 4;
        }
        else {
            kind = 0;
        }
        if (result != 2) {
            std::cout << "parsing packet cmd fail\n";
            send_packet(conn, "");
        }
                              
        if (kind == 2) {
            auto it = mem_wr_watchpoints.erase(watchpoint);
            if (it != 0) {
                //std::cout << "delete wr watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "OK");
            }
            else {
                std::cout << "fail in delete wr watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "");
            }                
        }
        else if (kind == 3) {
            auto it = mem_rd_watchpoints.erase(watchpoint);
            if (it != 0) {
                //std::cout << "delete rd watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "OK");            
            }
            else {
                std::cout << "fail in delete wr watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "");
            }

        }
        else if (kind == 4) {
            auto it0 = mem_wr_watchpoints.erase(watchpoint);
            auto it1 = mem_rd_watchpoints.erase(watchpoint);
            if ( (it0 != 0) && (it1 != 0)) {
                //std::cout << "delete rw watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "OK");            
            }
            else {
                std::cout << "fail in delete wr watchpoint set to address " <<  watchpoint << std::endl;
                send_packet(conn, "");
            }
            
        }
        else {
            send_packet(conn, "");
        }            
        
    }

    bool Debug::find_watchpoint() {
        mem_io_type_t mem_io_type;
        uint64_t mem_addr;
        uint64_t mem_size;
        mem_watchpoint_t test_point;
        bool hit_watchpoint;

        if (dbg_cpu32 != nullptr)
            std::tie(mem_io_type, test_point.mem_addr,test_point.addr_length) = dbg_cpu32->perf->get_watchpoint_info();
        else
            std::tie(mem_io_type, test_point.mem_addr,test_point.addr_length) = dbg_cpu64->perf->get_watchpoint_info();


        if (mem_io_type == MEM_IO_RD) {
            hit_watchpoint = false;
            auto search = mem_rd_watchpoints.find(test_point);
            if (search != mem_rd_watchpoints.end()) {
                hit_watchpoint = true;
                std::cout << "hit rd watch point\n";
            }                                  
        }
        else if  (mem_io_type == MEM_IO_WR) {
            hit_watchpoint = false;
            auto search = mem_wr_watchpoints.find(test_point);
            if (search != mem_wr_watchpoints.end()) {
                hit_watchpoint = true;
                std::cout << "hit wr watch point\n";
            }            
        } else {
            hit_watchpoint = false;
        }
        return hit_watchpoint;
    }

    void Debug::do_gdb_connect() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        auto result = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
        if (result < 0) {
            perror("fcntl O_NONBLOCK failed");
            exit(0);
        }
        int optval = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval,
                   sizeof(optval));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(1234);

        bind(sock, (struct sockaddr *) &addr, sizeof(addr));
        listen(sock, 1);

        while (1) {
            socklen_t len = sizeof(addr);
            errno = 0;
            conn = accept(sock, (struct sockaddr *)&addr, &len);
            if (errno != EAGAIN) {
                std::cout << "connecting\n";            

                auto result = fcntl(conn, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
                if (result < 0) {
                    perror("fcntl O_NONBLOCK failed");
                    exit(0);
                }
                break;
            } 
            else {
                //std::cout << "re-connect\n";                
            }
            wait(default_time*100);            
        }
    }

    void Debug::handle_gdb_loop() {
        std::cout << "Handle_GDB_Loop\n";

        do_gdb_connect();

        if (dbg_cpu32 != nullptr) {
            register_bank32 = dbg_cpu32->getRegisterBank();
        } else {
            register_bank64 = dbg_cpu64->getRegisterBank();
        }

        while (true) {
            std::string msg = "";
            while (msg.empty()) {
                msg = receive_packet();
                wait(default_time);  
                //std::cout << "wait message \n";
            }

            if (msg.empty() ) {
                std::cout << "remote connection seems to be closed, terminating ..."
                          << std::endl;
                break;
            } else if (msg == "+") {
                // NOTE: just ignore this message, nothing to do in this case
            } else if (boost::starts_with(msg, "qSupported")) {
                send_packet(conn, "PacketSize=256;swbreak+;hwbreak+;vContSupported+;multiprocess-;watchpoints-hw+;watchpoints-sw+");
            } else if (msg == "vMustReplyEmpty") {
                send_packet(conn, "");
            } else if (msg == "Hg0") {
                send_packet(conn, "OK");
            } else if (msg == "Hc0") {
                send_packet(conn, "");
            } else if (msg == "qTStatus") {
                send_packet(conn, "");
            } else if (msg == "?") {
                send_packet(conn, "S05");
            } else if (msg == "qfThreadInfo") {
                send_packet(conn, "");
            } else if (boost::starts_with(msg, "qL")) {
                send_packet(conn, "");
            } else if (msg == "Hc-1") {
                send_packet(conn, "OK");
            } else if (msg == "qC") {
                send_packet(conn, "-1");
            } else if (msg == "qAttached") {
                send_packet(conn, "0");  // 0 process started, 1 attached to process
            } else if (msg == "g") {

                //std::stringstream stream;
                //stream << std::setfill('0') << std::hex;
                std::string out_str = "";
                for (int i = 0; i < 32; i++) {
                    if (cpu_type == riscv_tlm::RV32) {                        
                        //auto tmp = int_to_string_byte_reverse(register_bank32->getValue(i));
                        auto tmp = int_to_string_byte_reverse(dbg_cpu32->getValue_rv32(i));
                        out_str = out_str + tmp;                        
                    }
                    else if (cpu_type == riscv_tlm::RV64) {
                        auto tmp = int_to_string_byte_reverse(dbg_cpu64->getValue_rv64(i));
                        out_str = out_str + tmp;                            
                    }
                    else {
                        std::cout << "Error\n";
                    }
                }
                send_packet(conn, out_str);
            } else if (boost::starts_with(msg, "p")) {
                long n = strtol(msg.c_str() + 1, nullptr, 16);
                std::uint64_t reg_value = 0;
                if (n < 32) {
                    if (cpu_type == riscv_tlm::RV32) {                        
                        reg_value = dbg_cpu32->getValue_rv32(n);                        
                    } else {                        
                        reg_value = dbg_cpu64->getValue_rv64(n);                        
                    }
                } else if (n == 32) {
                    if (cpu_type == riscv_tlm::RV32) {                        
                        reg_value = dbg_cpu32->getPC_rv32();                        
                    } else {                        
                        reg_value = dbg_cpu64->getPC_rv64();                        
                    }
                } else {
                    // see: https://github.com/riscv/riscv-gnu-toolchain/issues/217
                    // risc-v register 834
                    if (cpu_type == riscv_tlm::RV32) {                        
                        reg_value = dbg_cpu32->getCSR_rv32(n - 65);                        
                    } else {                        
                        reg_value = dbg_cpu64->getCSR_rv64(n - 65);                        
                    }
                }
                std::stringstream stream;
                stream << std::setfill('0') << std::hex;
                if (cpu_type == riscv_tlm::RV32) {
                    stream << std::setw(8) << htonl(reg_value);
                } else {
                    stream << std::setw(16) << htonl(reg_value);
                }
                send_packet(conn, stream.str());
            } else if (boost::starts_with(msg, "P")) {
                char *pEnd;
                long reg = strtol(msg.c_str() + 1, &pEnd, 16);
                //int val = strtol(pEnd + 1, nullptr, 16);
                auto val = string_to_hex(pEnd + 1);
                
                if (reg < 32) {
                    if (cpu_type == riscv_tlm::RV32) {                        
                        dbg_cpu32->setValue_rv32(reg , val);                        
                    } else {                        
                        dbg_cpu64->setValue_rv64(reg , val);                        
                    }
                }
                else {
                    if (cpu_type == riscv_tlm::RV32) {                        
                        dbg_cpu32->setPC_rv32(val);                        
                    } else {                        
                        dbg_cpu64->setPC_rv64(val);                        
                    }
                }
                send_packet(conn, "OK");
            } else if (boost::starts_with(msg, "m")) {

                auto string_out = do_rd_mem_cmd(msg);
                send_packet(conn, string_out.str());
                
            } else if (boost::starts_with(msg, "M")) {
                do_wr_mem_cmd(msg);                
                send_packet(conn, "OK");
            } else if (boost::starts_with(msg, "X")) {
                uint32_t start_addr,dat_size;
                std::string dat_out;
                parsing_load_cmd(msg);
                send_packet(conn, "OK");  // binary data suuport
            } else if (msg == "qOffsets") {
                send_packet(conn, "Text=0;Data=0;Bss=0");
            } else if (msg == "qSymbol::") {
                send_packet(conn, "OK");
            } else if (msg == "vCont?") {
                send_packet(conn, "vCont;cst");
            } else if (msg == "c") {
                gdb_continue_e.notify();                
                //gdb_continue_op();
            } else if (msg == "s") {
                gdb_step_op();
            } else if (boost::starts_with(msg, "vKill")) {
                send_packet(conn, "OK");
                break;
            } else if (boost::starts_with(msg, "Z4")) {
                insert_watchpoint(4,msg);               
            } else if (boost::starts_with(msg, "z4")) {
                delete_watchpoint(4,msg);
            } else if (boost::starts_with(msg, "Z3")) {
                insert_watchpoint(3,msg);               
            } else if (boost::starts_with(msg, "z3")) {
                delete_watchpoint(3,msg);
            } else if (boost::starts_with(msg, "Z2")) {
                insert_watchpoint(2,msg);                                               
            } else if (boost::starts_with(msg, "z2")) {
                delete_watchpoint(2,msg);                
            } else if (boost::starts_with(msg, "Z1")) {
                char *pEnd;
                long addr = strtol(msg.c_str() + 3, &pEnd, 16);
                breakpoints.insert(addr);
                std::cout << "Breakpoint set to address 0x" << std::hex << addr << std::endl;
                send_packet(conn, "OK");
            } else if (boost::starts_with(msg, "z1")) {
                char *pEnd;
                long addr = strtol(msg.c_str() + 3, &pEnd, 16);
                breakpoints.erase(addr);
                send_packet(conn, "OK");
            } else if (boost::starts_with(msg, "z0")) {
                char *pEnd;
                long addr = strtol(msg.c_str() + 3, &pEnd, 16);
                breakpoints.erase(addr);
                send_packet(conn, "");
            } else if (boost::starts_with(msg, "Z0")) {
                char *pEnd;
                long addr = strtol(msg.c_str() + 3, &pEnd, 16);
                breakpoints.insert(addr);
                std::cout << "Breakpoint set to address 0x" << std::hex << addr << std::endl;
                send_packet(conn, "OK");
            } else {
                std::cout << "unsupported message '" << msg
                          << "' detected, terminating ..." << std::endl;
                break;
            }
            wait(default_time);
        }
    }

    std::string Debug::compute_checksum_string(const std::string &msg) {
        unsigned sum = 0;
        for (auto c: msg) {
            sum += unsigned(c);
        }
        sum = sum % 256;

        char low = nibble_to_hex[sum & 0xf];
        char high = nibble_to_hex[(sum & (0xf << 4)) >> 4];

        return {high, low};
    }

}
