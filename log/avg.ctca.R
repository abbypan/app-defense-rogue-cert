
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1], header= FALSE)

colnames(df) <- c("url", "type", "time")
 
df_hs = df %>% 
    #mutate(prev_url = lag(url)) %>% 
    mutate(prev_result = lag(time)) %>% 
    filter(type == "ctca") %>% 
    mutate(time = as.double(time)) %>%
    group_by(url, prev_result) %>% 
    summarise(
              avg_time=mean(time), 
              median_time=median(time), 
              .groups = 'drop'
    )

dstf <- paste0(args[1] , ".stat")

colnames(df_hs) <- NULL
df_hs %>% write.table(dstf, col.names = FALSE, row.names = FALSE, quote = FALSE, sep="," )
