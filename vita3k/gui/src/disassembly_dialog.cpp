#include <gui/functions.h>
#include "private.h"
#include <cpu/functions.h>
#include <kernel/state.h>
#include <fmt/format.h>
#include <set>
#include <string>
#include <vector>

namespace gui {

// Usar um conjunto para armazenar os breakpoints
static std::set<uint32_t> breakpoints;
static std::vector<std::string> breakpoint_strings;  // Para armazenar os endereços formatados como string

void add_breakpoint(uint32_t addr) {
    if (breakpoints.find(addr) == breakpoints.end()) {
        breakpoints.insert(addr);
        breakpoint_strings.push_back(fmt::format("0x{:08X}", addr));
    }
}

bool check_breakpoint(uint32_t addr) {
    return breakpoints.find(addr) != breakpoints.end();
}

static void evaluate_code(GuiState &gui, EmuEnvState &emuenv, uint32_t from, uint32_t count, bool thumb) {
    gui.disassembly.clear();

    if (emuenv.kernel.threads.empty()) {
        gui.disassembly.emplace_back("Nothing to disassemble.");
        return;
    }

    uint16_t size = 1;
    uint32_t addr = from;

    for (std::uint32_t a = 0; a < count && size != 0; a++) {
        // Verifica se o endereço está no conjunto de breakpoints
        if (check_breakpoint(addr)) {
            gui.disassembly.emplace_back(fmt::format("Breakpoint hit at {:08X}", addr));
            break;
        }

        // Checa se o endereço é válido
        size_t addr_page = addr / KiB(4);
        if (addr_page == 0 || !is_valid_addr(emuenv.mem, addr_page * KiB(4))) {
            gui.disassembly.emplace_back(fmt::format("Disassembled {} instructions.", a));
            break;
        }

        // Desmonta a instrução e mostra na GUI
        std::string disasm = fmt::format("{:0>8X}: {}",
            addr, disassemble(*emuenv.kernel.threads.begin()->second->cpu.get(), addr, thumb, &size));
        gui.disassembly.emplace_back(disasm);
        addr += size;
    }
}

void reevaluate_code(GuiState &gui, EmuEnvState &emuenv) {
    std::string address_string = std::string(gui.disassembly_address);
    std::string count_string = std::string(gui.disassembly_count);

    uint32_t address = 0, count = 0;
    if (!address_string.empty())
        address = static_cast<uint32_t>(std::stol(address_string, nullptr, 16));
    if (!count_string.empty())
        count = static_cast<uint32_t>(std::stol(count_string));
    bool thumb = gui.disassembly_arch == "THUMB";

    evaluate_code(gui, emuenv, address, count, thumb);
}

static const char *archs[] = {
    "ARM",
    "THUMB",
};

void draw_disassembly_dialog(GuiState &gui, EmuEnvState &emuenv) {
    ImGui::Begin("Disassembly", &gui.debug_menu.disassembly_dialog);
    ImGui::BeginChild("disasm", ImVec2(0, -(ImGui::GetTextLineHeightWithSpacing() + 10)));

    // Exibe as instruções de desassemblagem
    for (const std::string &assembly : gui.disassembly) {
        ImGui::Text("%s", assembly.c_str());
    }

    ImGui::EndChild();

    ImGui::Separator();

    ImGui::BeginChild("disasm_info", ImVec2(0, ImGui::GetTextLineHeightWithSpacing() + 10));

    // Caixa de texto para entrada do endereço de início
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
    ImGui::Text("Address");
    ImGui::SameLine();
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 4);
    ImGui::PushItemWidth(10 * 8);
    if (ImGui::InputText("##disasm_addr", gui.disassembly_address, 9,
            ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
        reevaluate_code(gui, emuenv);
    }
    ImGui::PopItemWidth();
    ImGui::SameLine();

    // Caixa de texto para a contagem de instruções
    ImGui::Text("Count");
    ImGui::SameLine();
    ImGui::PushItemWidth(10 * 4);
    if (ImGui::InputText("##disasm_count", gui.disassembly_count, 5,
            ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
        reevaluate_code(gui, emuenv);
    }
    ImGui::PopItemWidth();
    ImGui::SameLine();

    // Seletor de arquitetura (ARM ou THUMB)
    ImGui::Text("Arch");
    ImGui::SameLine();
    if (ImGui::BeginCombo("##disasm_arch", gui.disassembly_arch.c_str())) {
        for (const char *arch : archs) {
            bool is_selected = gui.disassembly_arch == arch;
            if (ImGui::Selectable(arch, is_selected)) {
                gui.disassembly_arch = arch;
                reevaluate_code(gui, emuenv);
            }
            if (is_selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::Separator();

    // Campo para adicionar um novo breakpoint
    ImGui::Text("Add Breakpoint");
ImGui::SameLine();
ImGui::PushItemWidth(10 * 8);
if (ImGui::InputText("##breakpoint_addr", gui.breakpoint_address, 9, ImGuiInputTextFlags_CharsHexadecimal)) {
    // Se o usuário pressionar Enter, adiciona o breakpoint
    uint32_t addr = static_cast<uint32_t>(std::stol(gui.breakpoint_address, nullptr, 16));
    add_breakpoint(addr);
}
ImGui::PopItemWidth();

    ImGui::Separator();

    // Exibe a lista de breakpoints
    ImGui::Text("Breakpoints:");
    for (const std::string &bp : breakpoint_strings) {
        ImGui::BulletText("%s", bp.c_str());
    }

    ImGui::EndChild();

    ImGui::End();
}

} // namespace gui
