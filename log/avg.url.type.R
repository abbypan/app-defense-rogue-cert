
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1], header= FALSE)

colnames(df) <- c("url", "type", "time")
 
df_hs = df %>% group_by(url, type) %>% summarise(
                                                         avg_time=mean(time), 
                                                         median_time=median(time), 
                                                         .groups = 'drop')


dstf <- paste0(args[1] , ".stat.csv")

df_hs %>% write.table(dstf, col.names = TRUE, row.names = FALSE, quote = FALSE, sep="," )

