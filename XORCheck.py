import idautils
import idaapi
import idc

def main():
    print "\n\n\n---------------- XORCheck ---------------"
    print "Interesting XORs:"
    ea = MinEA()

    while ea < MaxEA():
        ea = FindText(ea, SEARCH_DOWN, 0, 0, "xor")
        eCode = idc.isCode(idc.GetFlags(ea))
        if not eCode or ea == idc.BADADDR:
            break
        if idc.GetOpnd(ea, 0) == idc.GetOpnd(ea, 1):
            ea = idc.NextHead(ea)
            continue
        func = idaapi.get_func(ea)
        if func.flags & FUNC_LIB:
            ea = idc.NextHead(ea)
            continue
        print "loc: ", hex(ea), "dis: ", idc.GetDisasm(ea), "func: ", idc.get_func_name(ea)
        idc.MakeComm(ea, "XORs: check it!")
        ea = idc.NextHead(ea)


    print "\n--------------- XORCheck EOF --------------\n"
    
        
main()