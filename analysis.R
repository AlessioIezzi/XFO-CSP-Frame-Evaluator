require(data.table)
library(lubridate)

analisi = read.csv("10k_tranco_url_13-09.csv", stringsAsFactors = FALSE)


policy_definition <- table(analisi$policy_definition)

policy_definition

inconsistency <- table(analisi$inconsistency)

inconsistency

which_policy <- table(analisi$which_policy,analisi$policy_definition)

which_policy

policy <- table(analisi$which_policy)

policy

which_policy2 <- table(analisi$inconsistency,analisi$allow_from_inconsistency)

which_policy2