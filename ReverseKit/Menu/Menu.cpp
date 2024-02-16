#include "Menu.h"

#include <string>
#include <unordered_map>
#include <Windows.h>

#include "../ImGui/imgui.h"

#include "../Hooks/SetHooks.h"

#include "../Imports/Imports.h"
#include "../Instrumentation/InstrumentationCallback.h"
#include "../Threads/Threads.h"
#include "../Heaps/Heaps.h"

void DrawInstrumentationInformation()
{
	ImGui::Begin("[ReverseKit] Instrumentation");
	ImGui::SetWindowSize(ImVec2(600, 600), ImGuiCond_Once);

	if (ImGui::Button("Clear")) {
		function_calls.clear();
	}

	ImGui::Text("Press F1 to log system calls");
	ImGui::Columns(2, "instrumentation_columns", true);

	ImGui::Text("Function Name"); ImGui::NextColumn();
	ImGui::Text("Return Address"); ImGui::NextColumn();
	ImGui::Separator();

	for (auto& [function_name, return_address] : function_calls) {
		ImGui::Text("%s", function_name.c_str()); ImGui::NextColumn();
		ImGui::Text("%p", return_address); ImGui::NextColumn();
	}

	ImGui::End();
}

void DrawThreadInformation()
{
	ImGui::Begin("[ReverseKit] Active Threads");
	ImGui::SetWindowSize(ImVec2(600, 400), ImGuiCond_Once);

	ImGui::Columns(3, "thread_columns", true);

	ImGui::Text("Thread ID"); ImGui::NextColumn();
	ImGui::Text("CPU Usage"); ImGui::NextColumn();
	ImGui::Text(""); ImGui::NextColumn();
	ImGui::Separator();

	for (const auto& [threadId, cpuUsage] : threadInfo) {
		ImGui::Text("%lu", threadId); ImGui::NextColumn();
		ImGui::Text("%u%%", cpuUsage); ImGui::NextColumn();

		if (ImGui::Button("Suspend")) {
			if (const HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
				hThread != nullptr) {
				SuspendThread(hThread);
				CloseHandle(hThread);
			}
		}
		ImGui::NextColumn();
	}

	ImGui::End();
}

void DrawImports()
{
	ImGui::Begin("[ReverseKit] Imports");
	ImGui::SetWindowSize(ImVec2(600, 600), ImGuiCond_Once);

	ImGui::Columns(3, "import_columns", true);

	ImGui::Text("DLL Name"); ImGui::NextColumn();
	ImGui::Text("Function Name"); ImGui::NextColumn();
	ImGui::Text("Function Address"); ImGui::NextColumn();
	ImGui::Separator();

	for (const auto& [dllName, functionName, functionAddress] : imports) {
		ImGui::Text(dllName.c_str()); ImGui::NextColumn();
		ImGui::Text(functionName.c_str()); ImGui::NextColumn();
		ImGui::Text("%p", functionAddress); ImGui::NextColumn();
	}

	ImGui::End();

}

void DrawHookedFunctions()
{
	ImGui::Begin("[ReverseKit] Hooked Functions");
	ImGui::SetWindowSize(ImVec2(400, 600), ImGuiCond_Once);

	static std::unordered_map<std::string, std::vector<InterceptedCallInfo>> functionCalls;
	for (const auto& call : SetHooks::interceptedCalls)
		functionCalls[call.functionName].push_back(call);

	for (const auto& [fst, snd] : functionCalls)
	{
		const std::string& functionName = fst;
		const std::vector<InterceptedCallInfo>& calls = snd;

		ImGui::SetNextTreeNodeOpen(true, ImGuiCond_FirstUseEver);
		if (ImGui::CollapsingHeader(functionName.c_str()))
		{
			for (const auto& [functionName, additionalInfo] : calls)
			{
				if (ImGui::Selectable(additionalInfo.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick))
				{
					ImGui::SetClipboardText(additionalInfo.c_str());
				}
			}
		}
	}

	functionCalls.clear();

	ImGui::End();
}

const char* HeapFlagsStr(const DWORD flags)
{
	switch (flags)
	{
	case 0x00000001:
		return "LF32_FIXED";
	case 0x00000002:
		return "LF32_FREE";
	case 0x00000004:
		return "LF32_MOVEABLE";
	default:
		return "<invalid>";
	}
}

void DrawHeaps()
{
	ImGui::Begin("[ReverseKit] Heaps");
	ImGui::SetWindowSize(ImVec2(600, 600), ImGuiCond_Once);

	ImGui::Columns(3, "import_columns", true);

	ImGui::Text("Flags"); ImGui::NextColumn();
	ImGui::Text("ID"); ImGui::NextColumn();
	ImGui::Text("Address"); ImGui::NextColumn();
	ImGui::Separator();

	for (const auto& [address, id, flags] : heaps) {
		ImGui::Text("%s", HeapFlagsStr(flags)); ImGui::NextColumn();
		ImGui::Text("%i", id); ImGui::NextColumn();
		ImGui::Text("%p", address); ImGui::NextColumn();
	}

	ImGui::End();
}

void RenderUI()
{
	static bool showThreads = false;
	static bool showImports = true;
	static bool showHookedFunctions = false;
	static bool showInstrumentation = false;
	static bool showHeaps = false;

	RECT rect{};
	SystemParametersInfo(SPI_GETWORKAREA, 0, &rect, 0);
	const int screenWidth = rect.right - rect.left;
	[[maybe_unused]] int screenHeight = rect.bottom - rect.top;
	const ImVec2 windowSize(440, 0);

	ImGui::SetNextWindowPos(ImVec2((screenWidth / 2) - (windowSize.x / 2), 0));
	ImGui::SetNextWindowSize(windowSize);

	ImGui::Begin("[ReverseKit] Main Menu", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

	const auto activeButtonColor = ImVec4(0.2f, 0.6f, 1.0f, 1.0f);
	const auto inactiveButtonColor = ImVec4(0.3f, 0.3f, 0.3f, 1.0f);

	if (showImports)
		ImGui::PushStyleColor(ImGuiCol_Button, activeButtonColor);
	else
		ImGui::PushStyleColor(ImGuiCol_Button, inactiveButtonColor);

	if (ImGui::Button("Imports"))
		showImports = !showImports;

	ImGui::PopStyleColor();

	ImGui::SameLine();

	if (showHookedFunctions)
		ImGui::PushStyleColor(ImGuiCol_Button, activeButtonColor);
	else
		ImGui::PushStyleColor(ImGuiCol_Button, inactiveButtonColor);

	if (ImGui::Button("Hooked Functions"))
		showHookedFunctions = !showHookedFunctions;

	ImGui::PopStyleColor();

	ImGui::SameLine();

	if (showThreads)
		ImGui::PushStyleColor(ImGuiCol_Button, activeButtonColor);
	else
		ImGui::PushStyleColor(ImGuiCol_Button, inactiveButtonColor);

	if (ImGui::Button("Threads"))
		showThreads = !showThreads;

	ImGui::PopStyleColor();

	ImGui::SameLine();

	if (showInstrumentation)
		ImGui::PushStyleColor(ImGuiCol_Button, activeButtonColor);
	else
		ImGui::PushStyleColor(ImGuiCol_Button, inactiveButtonColor);

	if (ImGui::Button("Instrumentation"))
		showInstrumentation = !showInstrumentation;

	ImGui::PopStyleColor();

	ImGui::SameLine();

	if (showHeaps)
		ImGui::PushStyleColor(ImGuiCol_Button, activeButtonColor);
	else
		ImGui::PushStyleColor(ImGuiCol_Button, inactiveButtonColor);

	if (ImGui::Button("Heaps"))
		showHeaps = !showHeaps;

	ImGui::PopStyleColor();

	ImGui::End();

	if (showInstrumentation)
		DrawInstrumentationInformation();
	if (showThreads)
		DrawThreadInformation();
	if (showImports)
		DrawImports();
	if (showHookedFunctions)
		DrawHookedFunctions();
	if (showHeaps)
		DrawHeaps();
}