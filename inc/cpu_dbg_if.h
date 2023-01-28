#pragma once

#include <cstdint>
#include "systemc.h"
#include "tlm.h"

namespace riscv_tlm {

    class cpu_dbg_if : public sc_interface {
    public:
        //Memory interface
        virtual std::uint32_t readDataMem(std::uint32_t addr, int size) = 0 ;
        virtual void writeDataMem(std::uint32_t addr, std::uint32_t data, int size) = 0;
        //register interface 32bit
        virtual void setValue_rv32(unsigned int reg_num, uint32_t value) {}
        virtual uint32_t getValue_rv32(unsigned int reg_num) const {return 0;}

        virtual uint32_t getPC_rv32() const {return 0;}
        virtual void setPC_rv32(uint32_t new_pc) {}

        virtual uint32_t getCSR_rv32(int csr) { return 0;}
        virtual void setCSR_rv32(int csr, uint32_t value_in) {};

        //register interface 64bit
        virtual void setValue_rv64(unsigned int reg_num, uint64_t value) {}
        virtual uint64_t getValue_rv64(unsigned int reg_num) const {return 0;}

        virtual uint64_t getPC_rv64() const {return 0;}
        virtual void setPC_rv64(uint64_t new_pc) {}

        virtual uint64_t getCSR_rv64(int csr) {return 0;}
        virtual void setCSR_rv64(int csr, uint64_t value_in) {};


        //control
        virtual bool CPU_step() = 0;

    };

}
