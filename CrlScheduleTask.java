package com.dianju.signatureServer.webSignService;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.LocalDateTime;

/**
 * 同步crl证书
 */
@Configuration      //1.主要用于标记配置类，兼备Component的效果。
@EnableScheduling   // 2.开启定时任务
public class CrlScheduleTask {
    //3.添加定时任务   每天23点执行一次
    @Scheduled(cron = "0 0 0 * * ?")
    //或直接指定时间间隔，例如：5秒
    //@Scheduled(fixedRate=5000)
    private void configureTasks() {
        LdapUtil.testNew();
        System.err.println("执行证书定时任务时间: " + LocalDateTime.now());
    }

}
