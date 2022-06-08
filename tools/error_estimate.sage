# FDFB system parameters (assume the minimal 80 bit security level)
## LWE parameters
n = 700
Q = 2^32-65535
sigma = 2^38
q = 2^11
t = 2^2
## Ring-GSW parameters
N = 2^11
stigma = 3.2
## Gadget Matrix
L_RGSW = 2^11
l_RGSW = ceil(log(q, L_RGSW))
## Bootstrapping Key Parameters
L_boot = 2^11
l_boot = ceil(log(Q, L_boot))
# Key Switching Key Parameters
L_ksK = 2^6
l_ksK = ceil(log(q, L_ksK))
L_pK = 2^13
l_pK = ceil(log(Q, L_pK))

Ham_s = int(64)
E_s = Ham_s/N
Var_s =  Ham_s/N - (Ham_s/N)^2

# standard deviation of the final error err(Refresh(c)), modeled as Gaussian distribution
sigma_brK = 3.2
sigma_pK = 3.2
sigma_ksK = sigma

sigma_P = sqrt( 1/3*N*l_pK*L_pK^2*sigma_pK^2 )
sigma_BR = sqrt( 2/3*n*N*l_RGSW*L_RGSW^2*sigma_brK^2 )
sigma_KS = sqrt( 1/3*N*l_ksK*L_ksK^2*sigma_ksK^2 )
sigma_F = sqrt( 1/3*N*l_boot*L_boot^2*(sigma_BR^2+sigma_P^2) )


add_num = 128
# beta = sqrt( (q^2)/(Q^2) * add_num * (sigma_F^2 + sigma_BR^2 + sigma_KS^2) + 1/12 + 1/12*Ham_s )
beta = stigma
beta = sqrt(add_num)*beta # accumulated error after addition
# q = Q

# error probability per NAND
r = q/(2*t*beta)
p = int(log(1 - erf(r/sqrt(2)), 2))
# p = 1 - erf(r/sqrt(2))


print (float(beta))
print (p)