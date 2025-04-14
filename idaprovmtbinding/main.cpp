#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <hexrays.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <name.hpp>
#include <demangle.hpp>

struct FunctionBindCtx
{
	struct _bindings {
		cexpr_t* e;
		uintptr_t var;
		uintptr_t vmt;
		uintptr_t vfunc;
	};
	std::vector<_bindings> varFuncBinds;
};

struct vmt_assignment_finder_t : public ctree_visitor_t
{
	vmt_assignment_finder_t() : ctree_visitor_t(CV_FAST) {}

	

	int visit_expr(cexpr_t* e) override
	{
		if (e->op == cot_asg)
		{
			if (e->x && e->x->op == cot_ptr)
			{
				if (e->y && e->y->op == cot_ref)
				{
					if (e->x->x->x->op == cot_var)
					{
						ea_t varAddr = e->x->x->x->n->_value;
						ea_t vmtAddr = e->y->x->obj_ea;
						qstring name;
						if (get_name(&name, vmtAddr))
						{
							guessedTypes.emplace_back(e->obj_ea, varAddr, vmtAddr, 0);

							msg("Found VMT assignment at 0x%llX: %s\n",
								e->ea, name.c_str());
						}
					}
					else if (e->x->x->x && e->x->x->x->x && e->x->x->x->x->op == cot_var && e->x->x->op != cot_sub)
					{
						ea_t varAddr = e->x->x->x->x->n->_value;
						int offset = e->x->x->x->y->n->_value;
						ea_t vmtAddr = e->y->x->obj_ea;
						qstring name;
						if (get_name(&name, vmtAddr))
						{
							guessedTypes.emplace_back(e->obj_ea, varAddr, vmtAddr, offset);

							msg("Found VMT assignment at 0x%llX: %s\n",
								e->ea, name.c_str());
						}
					}
				}
			}
		}

		return 0;
	}

	int visit_insn(cinsn_t* insn) override
	{
		if (insn->op == cit_return)
		{
			returnVarAddr = insn->creturn->expr.n->_value;
		}

		return 0;
	}

	uint64 returnVarAddr;

	struct VarVMTBind
	{
		uint64_t func;
		uint64_t var;
		uint64_t vmt;
		uint64_t vmtOffset;
	};

	std::vector<VarVMTBind> guessedTypes;
};

struct vcall_finder_t : public ctree_visitor_t {
	vcall_finder_t() : ctree_visitor_t(CV_FAST) {}

	int visit_expr(cexpr_t* e) override
	{
		if (e->op != cot_call)
			return 0;

		if (e->x->op != cot_ptr)
		{
			segment_t* seg = getseg(e->x->obj_ea);
			if (seg)
			{
				qstring seg_name;
				get_segm_name(&seg_name, seg);
				if (seg_name == ".text")
				{
					msg("Address %a belongs to segment %s\n", e->x->obj_ea, seg_name.c_str());
					msg("Found regular call at 0x%llX\n", e->x->obj_ea);

					regularCalls.emplace_back(e->x->obj_ea);
				}
			}
			return 0;
		}

		uint64_t varAddr = 0;
		auto curX = e->x->x;

		while (true)
		{
			// @xtr: not for global instances, skip
			if (curX->op == cot_obj)
				return 0;

			if (curX->op != cot_var)
				curX = curX->x;
			else
			{
				varAddr = curX->n->_value;
				break;
			}
		}

		uint64_t vmtFuncOffset = 0;
		uint64_t vmtTableOffset = 0;
		curX = e->x->x;

		if (e->x->x->op == cot_cast)
		{
			if (e->x->x->x->op == cot_add)
			{
				vmtFuncOffset = e->x->x->x->y->n->_value;
			}
		}
		else if (e->x->x->op == cot_ptr)
		{
			if (e->x->x->x->op == cot_cast)
			{
				if (e->x->x->x->x->op == cot_add)
				{
					vmtTableOffset = e->x->x->x->x->y->n->_value;
				}
			}
		}

		for (ea_t reg_call_addr : regularCalls)
		{
			func_t* f = get_func(reg_call_addr);
			if (!f)
				continue;

			mba_ranges_t ranges;
			ranges.pfn = f;

			cfuncptr_t cfunc = decompile(ranges);
			if (!cfunc)
				continue;

			msg("Found virtual call through VMT at 0x%llX\n", e->ea);
			msg("Analyzing function at 0x%llX for VMT assignments...\n", f->start_ea);

			vmt_assignment_finder_t finder;
			finder.apply_to(&cfunc->body, nullptr);

			for (auto& vars : finder.guessedTypes)
			{
				if (finder.returnVarAddr == vars.var && vars.vmtOffset == vmtTableOffset)
				{

					xrefblk_t xref;
					for (bool ok = xref.first_from(vars.func, XREF_CODE); ok; ok = xref.next_from())
					{
						if (xref.type == fl_CF)
						{
							auto cfunc = decompile(get_func(xref.to));

							//vcall_finder_t finder;
							//finder.ctx = ctx;
							//finder.apply_to(&cfunc->body, nullptr);
							//finder.BindVirtualFunctions();
							//analyze_function_chain(xref.to, targetVar, bestVMTBinding, bestOffset);
						}
					}

					ctx->varFuncBinds.emplace_back(e, varAddr, vars.vmt, vars.vmt + vmtFuncOffset);
					msg("Found virtual function for 0x%llX at 0x%llX\n", e->ea, vars.vmt + vmtFuncOffset);
				}
			}
		}


		return 0;
	}

	void BindVirtualFunctions()
	{
		for (auto& vars : ctx->varFuncBinds)
		{
			cexpr_t* new_func = new cexpr_t();
			new_func->op = cot_obj;
			new_func->obj_ea = get_qword(vars.vfunc);

			vars.e->x = new_func;

			qstring vmt_name;
			if (!get_name(&vmt_name, vars.vmt))
				vmt_name = "UnknownClass";

			qstring demangled_name;
			demangle_name(&demangled_name, vmt_name.c_str(), MNG_SHORT_FORM);
			if (demangled_name.empty())
				demangled_name = vmt_name;

			for (char& c : demangled_name)
			{
				if (!isalnum(c) && c != '_')
					c = '_';
			}

			demangled_name.replace("const_", "");
			demangled_name.replace("_vftable_", "");
			demangled_name.replace("vftable", "");

			while (demangled_name.find("__") != qstring::npos)
				demangled_name.replace("__", "_");

			size_t start = demangled_name.find("::");
			if (start != qstring::npos)
				demangled_name = demangled_name.substr(start + 2);

			int index = (vars.vfunc - vars.vmt) / sizeof(uintptr_t);

			qstring new_func_name;
			new_func_name.sprnt("%s_func%03d", demangled_name.c_str(), index);

			set_name(new_func->obj_ea, new_func_name.c_str());
		}
	}

	FunctionBindCtx* ctx;
	std::vector<ea_t> regularCalls;
};


void process_current_function()
{
	ea_t ea_selection = get_screen_ea();
	if (ea_selection == BADADDR)
	{
		msg(MSG_TAG "Select a function address first\n");
		return;
	}

	func_t* func = get_func(ea_selection);
	if (!func)
	{
		msg(MSG_TAG "No function found at current address1.\n");
		return;
	}

	vdui_t* vu = open_pseudocode(func->start_ea, 0);
	if (!vu || !vu->cfunc)
	{
		msg(MSG_TAG "Failed to get pseudocode for function at 0x%llX\n", func->start_ea);
		return;
	}

	FunctionBindCtx ctx;

	vcall_finder_t finder;
	finder.ctx = &ctx;
	finder.apply_to(&vu->cfunc->body, nullptr);
	finder.BindVirtualFunctions();

	vu->refresh_ctext();
}

bool idaapi run(size_t args)
{
	process_current_function();
	return true;
}

plugmod_t* idaapi init() {
	/*  if (!init_hexrays_plugin())
	  {
		  msg(MSG_TAG "Hex-Rays is not available.\n");
		  return PLUGIN_SKIP;
	  }*/

	return PLUGIN_OK;
}

void idaapi term()
{

}

__declspec(dllexport) plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,
	term,
	run,
	"VMT Call Finder Plugin",
	"",
	"VMT Call Finder",
	"Ctrl+Shift+F"
};
