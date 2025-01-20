
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1], header= FALSE)

colnames(df) <- c("url", "type", "avgtime", "mediantime")
 
df_hs = df %>% group_by(type) %>% summarise(
                                                         avg_time=mean(avgtime), 
                                                         median_time=median(mediantime), 
                                                         .groups = 'drop')


dstf <- paste0(args[1] , ".csv")

df_hs %>% write.table(dstf, col.names = FALSE, row.names = FALSE, quote = FALSE, sep="," )
