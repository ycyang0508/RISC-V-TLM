/*!
 \file Debug.h
 \brief GDB connector
 \author Màrius Montón
 \date February 2021
 */
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef INC_DEBUG_H_
#define INC_DEBUG_H_

#define SC_INCLUDE_DYNAMIC_PROCESSES

#include "systemc"

#include "tlm.h"
#include "tlm_utils/simple_initiator_socket.h"


#include "CPU.h"
#include "Memory.h"

namespace riscv_tlm {

    class Debug : sc_core::sc_module {
    public:

        sc_port<cpu_dbg_if> cpu_dbg_port;


        Debug(riscv_tlm::CPURV32 *cpu, Memory *mem);
        Debug(riscv_tlm::CPURV64 *cpu, Memory *mem);

        ~Debug() override;

    private:
        static std::string compute_checksum_string(const std::string &msg);

        void send_packet(int m_conn, const std::string &msg);

        std::string receive_packet();
        void parsing_load_cmd(std::string cmd_in);
        void do_wr_mem_cmd(std::string cmd_in);
        std::stringstream do_rd_mem_cmd(std::string cmd_in);
        uint32_t string_to_hex(std::string string_in);
        std::string int_to_string_byte_reverse(uint32_t dat_in);

        void handle_gdb_loop();

        static constexpr size_t bufsize = 1024 * 8;
        char iobuf[bufsize]{};
        int conn;
        riscv_tlm::CPURV32 *dbg_cpu32;
        riscv_tlm::CPURV64 *dbg_cpu64;
        Registers<std::uint32_t> *register_bank32;
        Registers<std::uint64_t> *register_bank64;
        Memory *dbg_mem;
        tlm::tlm_generic_payload dbg_trans;
        unsigned char pyld_array[128]{};
        std::unordered_set<uint32_t> breakpoints;
        riscv_tlm::cpu_types_t cpu_type;
        sc_core::sc_time default_time{};
    };
}

#endif /* INC_DEBUG_H_ */
