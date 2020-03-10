package com.dianju.core;

import com.alibaba.fastjson.JSONObject;
import com.dianju.modules.messageAndException.controllers.TimerFilterDisk;
import com.dianju.modules.org.models.App;
import com.dianju.modules.org.models.Department;
import com.dianju.modules.org.models.RbacOperation;
import com.dianju.modules.org.models.RbacRole;
import com.dianju.modules.org.models.RbacRoleDao;
import com.dianju.modules.org.models.RbacRoleDaoImpl;
import com.dianju.modules.org.models.SystemDictionary;
import com.dianju.modules.org.models.user.ManageDepartment;
import com.dianju.modules.org.models.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.hibernate.internal.SessionImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import srvSeal.SrvSealUtil;

import javax.annotation.Resource;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.ServletContext;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.*;

//import com.dianju.modules.backupAndRecovery.controllers.backupRealization;

/**
 * 系统初始化加载类
 *
 * @author liuchao
 * @date 2016-3-15
 */
@Configuration
@SuppressWarnings("rawtypes")
public class SystemInit extends WebMvcConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    @PersistenceContext
    private EntityManager em;


    @Transactional
    public void init() {

        System.out.println("****************************************");
        System.out.println("**               系统初始化            **");
        System.out.println("****************************************");

        /**通用数据初始化*/
        //部门表初始化
        if ((Long)  em.createQuery("select COUNT(1) from Department").getSingleResult() ==0) {
            log.info("部门表为空。。。。初始化部门表。。。");
            em.merge(new Department("0000000000000000000001", "总行", "0000000000000000000000", (byte) 1, "0000","总行"));
            log.info("初始化部门表完成");
        }

        //菜单初始化 通用菜单
        /***
         * 提示 重要的话说三遍 这里初始化的是通用菜单,这里初始化的是通用菜单,这里初始化的是通用菜单
         * 通用菜单就是 所有平台都会共用的菜单
         *
         * 某个平台单独有的菜单请添加到最下面的各个平台模块中  可以通过搜索 各平台数据初始化 找到这些代码
         *
         */
        if ((Long) em.createQuery("select COUNT(1) from App").getSingleResult() == 0) {
            log.info("菜单表为空。。。。初始化菜单表。。。");

            
         
            em.merge(new App("1100", "", "定时任务日志", "20", "module.log.task", 1100)); 
            em.merge(new App("1101", "", "定时任务", "90", "module.task", 1101)); 
             

            em.merge(new App("80", "fa-sitemap", "组织机构管理", "0", "module.organization", 80));
            em.merge(new App("81", "", "部门管理", "80", "module.organization.section", 81));
            em.merge(new App("82", "", "用户管理", "80", "module.organization.user", 82));
            em.merge(new App("83", "", "角色管理", "80", "module.organization.role", 83));
            em.merge(new App("84", "", "电子工牌", "80", "module.organization.card", 84));

            em.merge(new App("90", "fa-th-large", "系统管理", "0", "module.system", 90));
            em.merge(new App("91", "", "授权信息", "90", "module.system.accredit", 91));
            em.merge(new App("92", "", "权限管理", "90", "module.system.authority", 92));
            em.merge(new App("93", "", "菜单管理", "90", "module.system.menu", 93));
            em.merge(new App("94", "", "系统字典", "90", "module.system.dictionary", 94));
            em.merge(new App("205", "", "数据导入", "90", "module.system.dataimport", 205));

            em.merge(new App("2", "fa-file-image-o", "印模中心", "0", "module.mold", 2));
            em.merge(new App("3", "", "印模申请", "2", "module.mold.apply", 3));
            em.merge(new App("4", "", "印模审批", "2", "module.mold.approval", 4));
            em.merge(new App("5", "", "印模管理", "2", "module.mold.manage", 5));

            em.merge(new App("10", "fa-pause-circle-o", "印章中心", "0", "module.seal", 10));
            em.merge(new App("11", "", "印章制作", "10", "module.seal.make", 11));
            em.merge(new App("12", "", "印章查询", "10", "module.seal.query", 12));
            em.merge(new App("13", "", "印章管理", "10", "module.seal.manage", 13));
            em.merge(new App("14", "", "我的印章", "10", "module.seal.myself", 14));

            em.merge(new App("20", "fa-pencil-square-o", "日志管理", "0", "module.log", 20));
            em.merge(new App("21", "", "系统操作日志", "20", "module.log.system", 21));
            em.merge(new App("22", "", "印章写入key日志", "20", "module.log.key", 22));

            /***
             * 提示 重要的话说三遍 这里初始化的是通用菜单,这里初始化的是通用菜单,这里初始化的是通用菜单
             * 通用菜单就是 所有平台都会共用的菜单
             *
             * 某个平台单独有的菜单请添加到最下面的各个平台模块中  可以通过搜索 各平台数据初始化 找到代码位置
             */

//            em.merge(new App("50", "fa-pause-circle-o", "合同中心", "0", "module.contract", 50));
//            em.merge(new App("51", "", "合同提交", "50", "module.contract.apply", 51));
//            em.merge(new App("52", "", "合同审批", "50", "module.contract.approve", 52));
//            em.merge(new App("53", "", "合同盖章", "50", "module.contract.seal", 53));
//            em.merge(new App("54", "", "合同打印及归档", "50", "module.contract.print", 54));
//            em.merge(new App("55", "", "日志查询", "50", "module.contract.log", 55));
//            em.merge(new App("56", "", "合同查询", "50", "module.contract.list", 56));

//            em.merge(new App("160", "fa-comments", "客户评价", "0", "module.customer", 160));
//            em.merge(new App("161", "", "客户评价统计", "160", "module.customer.satisfaction", 161));
//            em.merge(new App("162", "", "客户评价列表", "160", "module.customer.comments", 162));
//
//            em.merge(new App("120", "fa-file-movie-o", "广告中心", "0", "module.advertisement", 120));
//            em.merge(new App("121", "", "广告分组", "120", "module.advertisement.groups", 121));
//            em.merge(new App("122", "", "广告管理", "120", "module.advertisement.manage", 122));
//            em.merge(new App("123", "", "广告审批", "120", "module.advertisement.approval", 123));
                //下面部分为各平台独有的菜单, 不要放开,  如果有需要可以在最下方各个平台数据块中进行初始化
//            //服务端签章
//            em.merge(new App("23", "", "服务端盖章日志", "20", "module.log.server", 23));
//            em.merge(new App("30", "fa-shield", "证书中心", "0", "module.certificate", 30));//服务端签章
//            em.merge(new App("31", "", "证书登记", "30", "module.certificate.register", 31));
//            em.merge(new App("32", "", "证书管理", "30", "module.certificate.manage", 32));
//            em.merge(new App("60", "fa-puzzle-piece", "应用系统管理", "0", "module.adhibition", 60));//服务端签章
//            em.merge(new App("70", "fa-file-o", "模板中心", "0", "module.template", 70));//服务端签章
//            em.merge(new App("71", "", "模板管理", "70", "module.template.manage", 71));
//            em.merge(new App("72", "", "规则管理", "70", "module.template.rule", 72));
//            //标准平台
//            em.merge(new App("24", "", "章使用日志", "20", "module.log.seal", 24));
//            em.merge(new App("40", "fa-print", "文档中心", "0", "module.document", 40));//标准平台
//            em.merge(new App("42", "", "文档管理", "40", "module.document.manage", 42));
//            em.merge(new App("43", "", "打印设置", "40", "module.document.print", 43));
//            em.merge(new App("41", "", "我的文档", "40", "module.document.person", 41));
//            em.merge(new App("44", "", "文档办理", "40", "module.document.deal", 44));
//            em.merge(new App("45", "", "我的历史文档", "40", "module.document.historyPerson", 45));
//            em.merge(new App("46", "", "历史文档管理", "40", "module.document.historyManage", 46));
//            em.merge(new App("50", "fa-key", "设备管理", "0", "module.device", 50));
            //无纸化平台
            //em.merge(new App("73", "", "判定条件", "70", "module.template.criterion", 73));
            //em.merge(new App("74", "", "通用字典", "70", "module.template.generalDictionary", 74));
            //em.merge(new App("75", "", "模板功能", "70", "module.template.function.list", 75));
            //	em.merge(new App("95", "fa-database", "备份/恢复", "0", "module.backupAndRecovery",95));
            // em.merge(new App("96", "fa-bell", "消息异常管理", "0", "module.message", 96));
            // em.merge(new App("97", "", "我的消息", "96", "module.message.mine", 97));
            // em.merge(new App("98", "", "消息列表", "96", "module.message.list", 98));
            // em.merge(new App("200", "fa-terminal", "开发实例", "0", "module.demo", 200));
            // em.merge(new App("201", "", "列表实例", "200", "module.demo.list", 201));
            // em.merge(new App("202", "", "详情实例", "200", "module.demo.detail", 202));
            // em.merge(new App("110", "fa-pause-circle-o", "稽核中心", "0", "module.audit",110));
            // em.merge(new App("111", "", "一级稽核", "110", "module.audit.first",111));
            // em.merge(new App("112", "", "二级稽核", "110", "module.audit.second",112));
            log.info("初始化菜单表完成");
        }

        //权限初始化
        if ((Long) em.createQuery("select COUNT(1) from RbacOperation").getSingleResult() == 0) {
            log.info("权限表为空。。。。初始化权限表。。。");
            em.merge(new RbacOperation("1", "POST", "/user", "organization", "添加用户"));
            em.merge(new RbacOperation("10", "POST", "/role", "organization", "添加角色"));
            em.merge(new RbacOperation("11", "PUT", "/role", "organization", "修改角色"));
            em.merge(new RbacOperation("12", "DELETE", "/role", "organization", "删除角色"));
            em.merge(new RbacOperation("13", "GET", "/role/", "organization", "角色查询（单个）"));
            em.merge(new RbacOperation("14", "GET", "/role", "organization", "角色查询（全部角色）"));
            em.merge(new RbacOperation("15", "GET", "/roles", "organization", "角色（高级搜索）"));
            em.merge(new RbacOperation("16", "POST", "/operation", "system", "添加权限"));
            em.merge(new RbacOperation("17", "PUT", "/operation", "system", "修改操作权限"));
            em.merge(new RbacOperation("18", "DELETE", "/operation", "system", "操作权限删除"));
            em.merge(new RbacOperation("19", "GET", "/operation/", "system", "操作权限查询（单个）"));
            em.merge(new RbacOperation("2", "DELETE", "/user", "organization", "删除用户"));
            em.merge(new RbacOperation("21", "GET", "/operation", "system", "查询所有权限"));
            em.merge(new RbacOperation("22", "POST", "/department", "organization", "部门添加"));
            em.merge(new RbacOperation("23", "PUT", "/department", "organization", "部门修改"));
            em.merge(new RbacOperation("24", "DELETE", "/department", "organization", "部门删除"));
            em.merge(new RbacOperation("26", "POST", "/app", "system", "添加菜单"));
            em.merge(new RbacOperation("27", "PUT", "/app", "system", "修改菜单"));
            em.merge(new RbacOperation("28", "GET", "/app/", "system", "查询单个菜单"));
            em.merge(new RbacOperation("29", "GET", "/apps", "system", "查询菜单列表"));
            em.merge(new RbacOperation("3", "PUT", "/user", "organization", "修改用户"));
            em.merge(new RbacOperation("30", "DELETE", "/app", "system", "删除菜单"));
            em.merge(new RbacOperation("31", "GET", "/app", "system", "查询所有菜单"));
            em.merge(new RbacOperation("32", "POST", "/seal_image", "moulage", "印模申请"));
            em.merge(new RbacOperation("33", "DELETE", "/seal_image", "moulage", "删除印模"));
            em.merge(new RbacOperation("34", "PUT", "/seal_image", "moulage", "印模审批"));
            em.merge(new RbacOperation("35", "GET", "/seal_image/", "moulage", "查询单个印模"));
            em.merge(new RbacOperation("36", "GET", "/seal_image", "moulage", "判断印模名称唯一性"));
            em.merge(new RbacOperation("37", "GET", "/seal_image_thumb", "moulage", "查看印模缩略图"));
            em.merge(new RbacOperation("38", "GET", "/seal_images_record", "moulage", "获取当前用户印模申请记录"));
            em.merge(new RbacOperation("39", "GET", "/seal_images_approval", "moulage", "获取审批列表"));
            em.merge(new RbacOperation("4", "GET", "/users", "organization", "查询用户（列表）"));
            em.merge(new RbacOperation("40", "GET", "/seal_images", "moulage", "获取印模管理列表"));
            em.merge(new RbacOperation("101", "GET", "/userCollectInfo", "dashboard", "首页用户展示"));
            em.merge(new RbacOperation("102", "GET", "/userSeal/", "seal", "查看用户印章"));
            em.merge(new RbacOperation("103", "POST", "/seal_image_update", "moulage", "单个印模修改"));
            em.merge(new RbacOperation("104", "GET", "/deptLogSystems", "other", "部门系统日志"));
            em.merge(new RbacOperation("105", "GET", "/myLogSystems", "other", "我的系统日志"));
            em.merge(new RbacOperation("106", "GET", "/deptLogSealUses", "other", "部门盖章日志"));
            em.merge(new RbacOperation("107", "GET", "/myLogSealUses", "other", "我的盖章日志"));
            em.merge(new RbacOperation("108", "GET", "/myLogSealWriteToKeys", "other", "我的章写入key日志"));
            em.merge(new RbacOperation("109", "GET", "/deptLogSealWriteToKeys", "other", "部门章写入key日志"));
            em.merge(new RbacOperation("110", "GET", "/sealCollectInfo", "dashboard", "首页印章展示"));
            em.merge(new RbacOperation("111", "POST", "/new_seal", "seal", "新建印章"));
            em.merge(new RbacOperation("41", "POST", "/seal", "seal", "制作印章"));
            em.merge(new RbacOperation("42", "DELETE", "/seal", "seal", "删除印章"));
            em.merge(new RbacOperation("43", "POST", "/user_seals", "seal", "印章授权"));
            em.merge(new RbacOperation("44", "PUT", "/seal", "seal", "修改印章"));
            em.merge(new RbacOperation("45", "GET", "/seal", "seal", "校验印章名称"));
            em.merge(new RbacOperation("46", "GET", "/seal/", "seal", "查询印章"));
            em.merge(new RbacOperation("47", "GET", "/seal_thumb", "seal", "查看印章缩略图"));
            em.merge(new RbacOperation("48", "GET", "/seals", "seal", "查询印章list"));
            em.merge(new RbacOperation("49", "GET", "/my_seals", "seal", "我的印章"));
            em.merge(new RbacOperation("5", "GET", "/user/", "organization", "查询用户（单个）"));
            em.merge(new RbacOperation("50", "GET", "/logSystems", "log", "查询系统操作日志列表"));
            em.merge(new RbacOperation("51", "GET", "/logServerSeals", "log", "查询服务端盖章日志列表"));
            em.merge(new RbacOperation("52", "GET", "/logSealWriteToKeys", "log", "查询印章写入key日志列表"));
            em.merge(new RbacOperation("53", "GET", "/logSealUses", "log", "查询章使用日志列表"));

            em.merge(new RbacOperation("54", "GET", "/logPrints", "print", "查询打印日志列表"));
            em.merge(new RbacOperation("55", "GET", "/logPrint", "print", "根据文档编号单个查询"));
            em.merge(new RbacOperation("56", "POST", "/document", "print", "添加打印文档"));
            em.merge(new RbacOperation("57", "DELETE", "/document", "print", "根据id删除打印文档"));
            em.merge(new RbacOperation("58", "GET", "/document", "print", "单个查找打印文档"));
            em.merge(new RbacOperation("59", "GET", "/documents", "print", "分页查询打印文档"));

            em.merge(new RbacOperation("6", "GET", "/user/exist", "organization", "查看登录用户名是否存在"));

            em.merge(new RbacOperation("60", "PATCH", "/document", "print", "打印机的控制"));
            em.merge(new RbacOperation("61", "POST", "/document_print_setting", "print", "添加打印权限设置"));
            em.merge(new RbacOperation("62", "GET", "/documents_print_setting", "print", "分页查询打印权限设置"));
            em.merge(new RbacOperation("63", "PUT", "/document_print_setting", "print", "打印设置详情中的修改打印份数"));
            em.merge(new RbacOperation("64", "POST", "/cert", "certificate", "添加证书"));
            em.merge(new RbacOperation("65", "DELETE", "/cert", "certificate", "删除证书"));
            em.merge(new RbacOperation("66", "GET", "/certs", "certificate", "查询证书列表"));
            em.merge(new RbacOperation("67", "GET", "/all_certs", "certificate", "查询所有证书"));
            em.merge(new RbacOperation("68", "PUT", "/dictionary", "system", "修改系统字典配置"));
            em.merge(new RbacOperation("69", "GET", "/dictionary", "system", "查询系统字典列表"));

//			em.merge(new RbacOperation("70", "POST", "/device", "device", "添加设备"));
//			em.merge(new RbacOperation("71", "DELETE", "/device", "device", "删除设备"));
//			em.merge(new RbacOperation("72", "PUT", "/device", "device", "修改设备"));
//			em.merge(new RbacOperation("73", "GET", "/device/", "device", "查询设备"));
//			em.merge(new RbacOperation("74", "GET", "/devices", "device", "查询设备列表"));
//			em.merge(new RbacOperation("75", "GET", "/devices_log", "device", "设备使用日志"));
//			em.merge(new RbacOperation("76", "GET", "/cert_name", "certificate", "校验证书名称"));
            em.merge(new RbacOperation("80", "GET", "/word_card", "organization", "查询电子工牌"));
            em.merge(new RbacOperation("81", "POST", "/card", "organization", "添加电子工牌"));
            em.merge(new RbacOperation("82", "DELETE", "/card", "organization", "添加电子工牌"));
            em.merge(new RbacOperation("83", "POST", "/userCard/exist", "organization", "查询电子工牌是否存在"));


            //客户评价
            em.merge(new RbacOperation("91", "GET", "/satisfactionSurveys", "satisfactionSurvey", "客户评价查询"));
            //验证证书是否重复
            em.merge(new RbacOperation("7", "GET", "/user/existUserCert", "organization", "验证证书是否重复"));
            log.info("初始化权限表完成");
        }

        //角色初始化
        RbacRole r1=null, r2=null, r3=null, r4=null, r5=null, r6=null, r7=null, r8=null,r9=null,r10=null,r11=null;
        if ((Long) em.createQuery("select COUNT(1) from RbacRole").getSingleResult() == 0) {
            log.info("角色表为空。。。。初始化角色表。。。");

            r1 = new RbacRole("1", "=1=", "系统管理员", 1);
            r1.addRbacApp("2", "3", "4", "5", "10", "11", "12", "13", "14", "20", "21", "22", "80", "81", "82", "83", "84", "90", "91", "92", "93", "94", "205","1100","1101");
            em.merge(r1);

            r2 = new RbacRole("2", "=1=", "印模审计员", 1);
            r2.addRbacOperation("34", "35", "39", "40", "41", "42", "45", "46", "48", "49", "101", "105", "111");
            r2.addRbacApp("2", "4", "10", "11", "14", "20", "21");
            em.merge(r2);

             r3 = new RbacRole("3", "=", "印模印章管理员", 0);
            r3.addRbacOperation("32", "33", "35", "36", "37", "38", "40", "43", "44", "45", "46", "47", "48", "49", "50", "52", "53", "101", "102", "105", "107", "108", "109", "110");
            r3.addRbacApp("2", "3", "5", "10", "12", "13", "14", "20", "21", "22");
            em.merge(r3);

            r4 = new RbacRole("4", "=", "用户管理员", 0);
            r4.addRbacOperation("1", "2", "3", "4", "5", "6", "14", "101", "102", "105","7");
            r4.addRbacApp("20", "21", "80", "82");
            em.merge(r4);

            r5 = new RbacRole("5", "=", "日志审计员", 1);
            r5.addRbacOperation("101", "104", "105", "106", "109");
            r5.addRbacApp("20", "21", "22");
            em.merge(r5);

            r6 = new RbacRole("6", "=", "盖章用户", 1);
            r6.addRbacOperation("105", "107");
            r6.addRbacApp("20", "21");
            em.merge(r6);

            r7 = new RbacRole("7", "=", "柜员用户", 1);
            em.merge(r7);

            log.info("初始化角色表完成");
        }

        //用户初始化
        long time = (long) (System.currentTimeMillis() / 1000);
        //获取数据库方言
        String s = ((SessionImpl) em.unwrap(org.hibernate.Session.class)).getFactory().getDialect().getClass().getName();
        if (s.equals("org.hibernate.dialect.MySQL5Dialect")) {
            Util.DATABASE_TYPE = "mysql";
        } else if (s.equals("org.hibernate.dialect.Oracle10gDialect")) {
            Util.DATABASE_TYPE = "oracle";
        } else if (s.equals("org.hibernate.dialect.SQLServer2008Dialect")) {
            Util.DATABASE_TYPE = "sqlserver";
        }else if (s.equals("org.hibernate.dialect.DmDialect")) {
            Util.DATABASE_TYPE = "dmserver";
        } else {
            Util.DATABASE_TYPE = "unknown";
        }
        log.info(Util.DATABASE_TYPE);

        if ((Long) em.createQuery("select COUNT(1) from User u where 1=1").getSingleResult() == 0) {
            log.info("用户表为空。。。。初始化用户表。。。");
            User u = new User("u1", 1461055397, "1", "0", "344289076@qq.com", (byte) 1, "admin", "管理员", "49dc52e6bf2abe5ef6e2bb5b0f1ee2d765b922ae6cc8b95d39dc06c21c848f8c", time, (byte) 0, Util.getTimeStampOfNow(), (byte) 0);
            u.setDepartment(new Department("0000000000000000000001"));
            u.getRbacRoles().add(new RbacRole("1", "=1=", "系统管理员", 1));
            u.getManageDepartments().add(new ManageDepartment("1", (byte) 1, "0000000000000000000001", "1"));
            em.merge(u);

            log.info("初始化用户表完成");
        }

        //系统字典初始化
        if ((Long) em.createQuery("select COUNT(1) from SystemDictionary").getSingleResult() == 0) {
            log.info("系统字典表为空。。。。初始化系统字典表。。。");
            em.merge(new SystemDictionary("1", (byte) 1, "upload_path", "'e:/"));
            em.merge(new SystemDictionary("4", (byte) 1, "approve_seal_role", "2,3"));
            em.merge(new SystemDictionary("5", (byte) 1, "update_password_time_out", "100"));
            em.merge(new SystemDictionary("6", (byte) 1, "approle_role", "[{\"id\":\"1\",\"name\":\"印模审批权限\"},{\"id\":\"2\",\"name\":\"模板审批权限\"},{\"id\":\"3\",\"name\":\"印章审批权限\"}]"));
            em.merge(new SystemDictionary("7", (byte) 1, "seal_types", "[{\"v\":\"1\",\"title\":\"公章\"},{\"v\":\"2\",\"title\":\"公章(法人章)\"},{\"v\":\"3\",\"title\":\"公章(合同章)\"},{\"v\":\"4\",\"title\":\"公章(党章)\"},{\"v\":\"5\",\"title\":\"公章(财务章)\"},{\"v\":\"6\",\"title\":\"公章(工会章)\"},{\"v\":\"7\",\"title\":\"个人章\"},{\"v\":\"8\",\"title\":\"个人章(手写签名)\"},{\"v\":\"9\",\"title\":\"个人章(文字签名)\"}]"));
            em.merge(new SystemDictionary("8", (byte) 1, "not_operations", "POST/api/serviceForMobile/Authentication;GET/api/dictionary;POST/api/updatePw;POST/api/cutLogin;GET/api/departments;GET/api/logout;POST/api/login;GET/api/userInfo;PUT/userInfo;POST/api/serviceForAip/*;GET/user/existUserCert;GET/api/getCaptcha;POST/api/verifyCaptcha;GET/api/getProofCode;"));
            em.merge(new SystemDictionary("9", (byte) 1, "not_logins", "/api/getUUIDCode;/api/serviceForMobile/Authentication;/api/serviceForMobile/getSealList;/api/serviceForMobile/getSealData;/api/loginNoPassword;/api/documentPrintBatch;/api/documentPrintSingle;/api/serviceForAip/;/api/getCaptcha;/api/verifyCaptcha;/api/autoPdfSeal;/api/getProofCode;"));
            em.merge(new SystemDictionary("23", (byte) 1, "passwordStrengthCheck", "^([\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*)$"));
            em.merge(new SystemDictionary("10", (byte) 1, "defaultLowerLevel", "true"));
            em.merge(new SystemDictionary("11", (byte) 1, "logLowerLevel", "false"));
            em.merge(new SystemDictionary("12", (byte) 1, "repeatLogin", "false"));
            em.merge(new SystemDictionary("13", (byte) 1, "verify_user_cert", "{\"certSn\": \"verify\",\"certDn\": \"verify\"}"));
            em.merge(new SystemDictionary("14", (byte) 1, "printControl", "5;0"));
            em.merge(new SystemDictionary("15", (byte) 1, "verify_captcha", "false"));
            em.merge(new SystemDictionary("16", (byte) 1, "password_error_times", "10"));
            em.merge(new SystemDictionary("17", (byte) 1, "password_error_num", "5"));
            em.merge(new SystemDictionary("18", (byte) 1, "authority_modules", "[{\"key\":\"dashboard\",\"value\":\"首页\"},{\"key\":\"organization\",\"value\":\"组织机构\"},{\"key\":\"moulage\",\"value\":\"印模中心\"},{\"key\":\"seal\",\"value\":\"印章中心\"},{\"key\":\"template\",\"value\":\"模板中心\"},{\"key\":\"certificate\",\"value\":\"证书中心\"},{\"key\":\"print\",\"value\":\"打印中心\"},{\"key\":\"device\",\"value\":\"设备管理\"},{\"key\":\"adhibition\",\"value\":\"应用系统管理\"},{\"key\":\"log\",\"value\":\"日志管理\"},{\"key\":\"system\",\"value\":\"系统管理\"},{\"key\":\"other\",\"value\":\"其他\"}]"));
            em.merge(new SystemDictionary("19", (byte) 1, "synthetic_type", "pdf"));
            em.merge(new SystemDictionary("24", (byte) 1, "passwordStrengthNarration", "必须包含大小写字母、数字"));
            em.merge(new SystemDictionary("25", (byte) 1, "passwordLengthMin", "8"));
            em.merge(new SystemDictionary("26", (byte) 1, "passwordLengthMax", "20"));
            em.merge(new SystemDictionary("27", (byte) 1, "customerComments", "[{\"id\":\"1\",\"name\":\"非常满意\",\"status\":\"1\"},{\"id\":\"2\",\"name\":\"满意\",\"status\":\"1\"},{\"id\":\"3\",\"name\":\"一般\",\"status\":\"1\"},{\"id\":\"4\",\"name\":\"不满意\",\"status\":\"1\"},{\"id\":\"5\",\"name\":\"超时退出\",\"status\":\"1\"},{\"id\":\"6\",\"name\":\"非常满意\",\"status\":\"0\"},{\"id\":\"7\",\"name\":\"非常满意\",\"status\":\"0\"},{\"id\":\"8\",\"name\":\"非常满意\",\"status\":\"0\"},{\"id\":\"9\",\"name\":\"非常满意\",\"status\":\"0\"},{\"id\":\"10\",\"name\":\"非常满意\",\"status\":\"0\"}]"));
            em.merge(new SystemDictionary("28", (byte) 1, "delete_temp_files", "{\"isDelete\":\"否\",\"dateType\":\"日\",\"dateNumber\":\"3\"}"));
            log.info("系统字典表完成");
        }

        //各平台数据初始化
        //标准平台
        if ((LicenseConfig.systemType & LicenseConfig.SystemType_Seal) == LicenseConfig.SystemType_Seal) {
            System.out.println("标准印章服务..............");
            em.merge(new App("24", "", "章使用日志", "20", "module.log.seal", 24));
            em.merge(new App("40", "fa-print", "文档中心", "0", "module.document", 40));//标准平台
            em.merge(new App("42", "", "文档管理", "40", "module.document.manage", 42));
            em.merge(new App("43", "", "打印设置", "40", "module.document.print", 43));

            r1 = em.find(RbacRole.class,"1");
            if (r1==null){
                r1 = new RbacRole("1", "=1=", "系统管理员", 1);
            }
            r6 = em.find(RbacRole.class,"6");
            if (r6==null){
                r6 = new RbacRole("6", "=", "盖章用户", 1);
            }
            r1.addRbacApp("24", "40", "42", "43");
            em.merge(r1);
            r6.addRbacApp("24");
            em.merge(r6);
            System.out.println("标准印章服务数据初始化完成..............");
        }

        //服务端签章
        if ((LicenseConfig.systemType & LicenseConfig.SystemType_Server) == LicenseConfig.SystemType_Server) {
            System.out.println("服务器签章服务........");
            em.merge(new App("23", "", "服务端盖章日志", "20", "module.log.server", 23));
            em.merge(new App("30", "fa-shield", "证书中心", "0", "module.certificate", 30));//服务端签章
            em.merge(new App("31", "", "证书登记", "30", "module.certificate.register", 31));
            em.merge(new App("32", "", "证书管理", "30", "module.certificate.manage", 32));
            em.merge(new App("60", "fa-puzzle-piece", "应用系统管理", "0", "module.adhibition", 60));//服务端签章
            em.merge(new App("70", "fa-file-o", "模板中心", "0", "module.template", 70));//服务端签章
            em.merge(new App("71", "", "模板管理", "70", "module.template.manage", 71));
            em.merge(new App("72", "", "规则管理", "70", "module.template.rule", 72));

            r1 = em.find(RbacRole.class,"1");
            if (r1==null){
                r1 = new RbacRole("1", "=1=", "系统管理员", 1);
            }

            r1.addRbacApp("23", "30", "31", "32", "60", "70", "71", "72");
            em.merge(r1);
            System.out.println("服务器签章服务数据初始化完成........");
        }

        //无纸化服务
        if ((LicenseConfig.systemType & LicenseConfig.SystemType_Paperless) == LicenseConfig.SystemType_Paperless) {
            System.out.println("无纸化服务");
            em.merge(new App("160", "fa-comments", "客户评价", "0", "module.customer", 160));
            em.merge(new App("161", "", "客户评价统计", "160", "module.customer.satisfaction", 161));
            em.merge(new App("162", "", "客户评价列表", "160", "module.customer.comments", 162));

            em.merge(new App("120", "fa-file-movie-o", "广告中心", "0", "module.advertisement", 120));
            em.merge(new App("121", "", "广告分组", "120", "module.advertisement.groups", 121));
            em.merge(new App("122", "", "广告管理", "120", "module.advertisement.manage", 122));
            em.merge(new App("123", "", "广告审批", "120", "module.advertisement.approval", 123));
            r1 = em.find(RbacRole.class,"1");
            if (r1==null){
                r1 = new RbacRole("1", "=1=", "系统管理员", 1);
            }

            r1.addRbacApp("120", "121", "122", "123","160", "161", "162");
            em.merge(r1);
            System.out.println("服务器签章服务数据初始化完成........");
        }
        //移动端服务
        if ((LicenseConfig.systemType & LicenseConfig.SystemType_MobileAuthorization) == LicenseConfig.SystemType_MobileAuthorization) {
            System.out.println("移动端服务");
        }
        //定制化服务
        if ((LicenseConfig.systemType & LicenseConfig.SystemType_Custom) == LicenseConfig.SystemType_Custom) {
            System.out.println("定制化服务");
        }

        //合同审批
        if (false){

        	if(em.find(RbacOperation.class,"10001")==null){
        		em.merge(new RbacOperation("10001", "GET", "/getContractFile/", "system", "下载合同文件"));
                em.merge(new RbacOperation("10002", "GET", "/contractLogGetPage", "system", "合同日志列表查询"));

                em.merge(new RbacOperation("10003", "POST", "/contract", "contract", "合同上传"));
                em.merge(new RbacOperation("10004", "POST", "/contract/approve", "contract", "合同审批"));
                em.merge(new RbacOperation("10005", "GET", "/contract/waitApproveList", "contract", "合同待审批列表查询"));
                em.merge(new RbacOperation("10006", "GET", "/contract/approvedList", "contract", "合同已审批列表查询"));

                em.merge(new RbacOperation("10007", "POST", "/contract/seal", "contract", "合同盖章"));
                em.merge(new RbacOperation("10008", "GET", "/contract/waitSealList", "contract", "合同待盖章列表查询"));
                em.merge(new RbacOperation("10009", "GET", "/contract/sealedList", "contract", "合同已盖章列表查询"));

                em.merge(new RbacOperation("10010", "POST", "/contract/print", "contract", "合同打印"));
                em.merge(new RbacOperation("10011", "GET", "/contract/printList", "contract", "合同打印列表查询"));

                em.merge(new RbacOperation("10012", "GET", "/contract/archive", "contract", "合同归档"));
                em.merge(new RbacOperation("10013", "GET", "/contract/archiveList", "contract", "合同归档列表查询"));
            }

            if (em.find(App.class,"50")==null){
                em.merge(new App("50", "fa-pause-circle-o", "合同中心", "0", "module.contract", 50));
                em.merge(new App("51", "", "合同提交", "50", "module.contract.apply", 51));
                em.merge(new App("52", "", "合同审批", "50", "module.contract.approve", 52));
                em.merge(new App("53", "", "合同盖章", "50", "module.contract.seal", 53));
                em.merge(new App("54", "", "合同打印及归档", "50", "module.contract.print", 54));
                em.merge(new App("55", "", "日志查询", "50", "module.contract.log", 55));
                em.merge(new App("56", "", "合同查询", "50", "module.contract.list", 56));
            }
        	
            //合同办理角色
            r8 = em.find(RbacRole.class,"8");
            if (r8==null){
                r8 = new RbacRole("8", "=", "合同办理用户", 1);
               
            }
            r8.addRbacApp("50","51","54");
            r8.addRbacOperation("10001","10003","10010","10011");
            em.merge(r8);

            //合同审批角色
            r9 = em.find(RbacRole.class,"9");
            if (r9==null){
                r9 = new RbacRole("9", "=", "合同审批用户", 1);
                
            }
            r9.addRbacApp("50","52");
            r9.addRbacOperation("10001","10004","10005","10006");
            em.merge(r9);

            //合同盖章角色
            r10 = em.find(RbacRole.class,"10");
            if (r10==null){
                r10 = new RbacRole("10", "=", "合同盖章用户", 1);
            }

            r10.addRbacApp("50","53");
            r10.addRbacOperation("10001","10007","10008","10009");
            em.merge(r10);


            //合同日志管理员
            r11 = em.find(RbacRole.class,"11");
            if (r11 == null){
                r11 = new RbacRole("11", "=", "合同日志管理员", 1);

            }

            r10.addRbacApp("50","55","56");
            r11.addRbacOperation("10002","10012","10013");
            em.merge(r11);

        }

        new Timer(true).schedule(
            new TimerTask() {
                public void run() {
                    ServletContext servletContext = SystemListener.servletContext;
                    String keyPath = (String) servletContext.getAttribute("KEYPATH");

                    Map map = (Map) servletContext.getAttribute("KEY");
                    try {
                        BufferedReader br = new BufferedReader(new FileReader(new File(keyPath)));
                        String s = null;
                        String s1 = "";
                        while ((s = br.readLine()) != null) {
                            s1 += s;
                        }
                        br.close();
                        String key = new String(Base64.decodeBase64(s1), "UTF-8");
                        ObjectMapper mapper = new ObjectMapper();
                        map = mapper.readValue(key, HashMap.class);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            }
            , new Date().getTime() + 10000, 7200000);
        //new Timer().schedule(new TimerFilterDisk(), new Date(), (Integer.parseInt("12")) * 3600000);
        new Timer().schedule(new TimerFilterDisk(), 10000);//查看数据库类型
        new Timer(true).schedule(//延时装载ocx
            new TimerTask() {
                public void run() {
                    if (System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1) {
                        SrvSealUtil srvSealUtil = (SrvSealUtil) Util.getBean("srvSealUtil");
                        System.out.println("开始装载OCX");
                        String javaversion = System.getProperty("sun.arch.data.model");
                        String ocxName = "/loadOCX/" + "HWPostil-Server-x" + javaversion + ".ocx";
                        //String ocxName = "/loadOCX/" + "HWPostil-x64.ocx";
                        String OCXPath = Util.getPath(ocxName);
                        if (OCXPath != null) {
                            System.out.println("OCXPath:" + OCXPath);
                            int loadOCX = srvSealUtil.setCtrlPath(OCXPath);
                            System.out.println("loadOCX:" + loadOCX);
                            System.out.println("OCX装载完毕");
                        } else {
                            System.out.println("未找到OCX");
                        }
                    }else{
                    	SrvSealUtil.verifyLic();
                    }
                }
            }, 10000);

        //删除无用文件，每天运行一次，每个月清除一次,清除周期可配置
        //new Timer().schedule(new TimerDeleteFile(), new Date(), 7200000);
        new Timer(true).schedule(
                new TimerTask() {
                    public void run() {
                        System.out.println("删除文件定时器启动");
                        Calendar now = Calendar.getInstance();
//            			System.out.println("年: " + now.get(Calendar.YEAR));
//            			System.out.println("月: " + (now.get(Calendar.MONTH) + 1) + "");
//            			System.out.println("日: " + now.get(Calendar.DAY_OF_MONTH));
                        int dateDD = now.get(Calendar.DAY_OF_MONTH);
                        String deleteTempFilesConfig = Util.getSystemDictionary("delete_temp_files");
                        JSONObject jsObj = JSONObject.parseObject(deleteTempFilesConfig);
                        String isDelete = jsObj.get("isDelete")+"";
                        String dateType = jsObj.get("dateType")+"";
                        int dateNumber = Integer.parseInt(jsObj.get("dateNumber")+"");
                        if(("是".equals(isDelete)||"否".equals(isDelete))&&("年".equals(dateType)||"月".equals(dateType)||"日".equals(dateType))&&(dateNumber>=1)){
                            if("是".equals(jsObj.get("isDelete"))){
                                if("日".equals(jsObj.get("dateType"))){
                                    if(dateDD%dateNumber==0){
                                        System.out.println("每隔"+dateNumber+"天删除服务器盖章文件，盖章文件保存日期为"+dateNumber+"天！");
                                    }
                                }else if("月".equals(jsObj.get("dateType"))){
                                    if(dateDD%dateNumber==0){
                                        System.out.println("每隔"+dateNumber+"个月删除服务器盖章文件，盖章文件保存日期为"+dateNumber+"个月！");
                                    }
                                }else{
                                    if(dateDD%dateNumber==0){
                                        System.out.println("每隔"+dateNumber+"年删除服务器盖章文件，盖章文件保存日期为"+dateNumber+"年！");
                                    }
                                }
                                DeleteTempFilesUtil.findAndDeleteFiles(dateType,dateNumber);
                            }else{
                                System.out.println("配置项为‘否’,缓存文件无需定时删除！");
                            }

                        }else{
                            System.out.println("缓存配置项出错,请修改或联系管理员！");
                        }

                    }
                }
                , 12000, 24*60*60*1000);//24*60*60*1000
    }

    /**通用数据初始化*/
    /**初始化系统数据**/
    //部门表初始化
//		    	 Query departmentCountQuery=em.createNativeQuery("select count(1) as count from department");
//		 	     departmentCountQuery.unwrap(SQLQuery.class).setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);
//				 if((((Map)departmentCountQuery.getSingleResult()).get("count")+"").equals("0")){
//			    log.info("部门表为空。。。。初始化部门表。。。");
//			 em.createNativeQuery("INSERT INTO department (id, created_at, status, text1, text2, updated_at, all_name, code, is_organization, name, other_parent_id, other_id, server_label) VALUES ("0000000000000000000001", "1461037000", "1", NULL, NULL, "1", "总行", "0000000000000000000000", "1", "总行", NULL, NULL, "0000");").executeUpdate();
//			 log.info("初始化部门表完成");
//		 }

//		 //菜单表初始化
//		 Query appCountQuery=em.createNativeQuery("select count(1) as count from app");
//		 appCountQuery.unwrap(SQLQuery.class).setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);
//		 if((((Map)appCountQuery.getSingleResult()).get("count")+"").equals("0")){
//			 log.info("菜单表为空。。。。初始化菜单表。。。");
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('10', 'fa-pause-circle-o', '印章中心', '10', '0', 'module.seal', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('11', '', '印章制作', '11', '10', 'module.seal.make', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('12', '', '印章查询', '12', '10', 'module.seal.query', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('13', '', '印章管理', '13', '10', 'module.seal.manage', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('14', '', '我的印章', '14', '10', 'module.seal.myself', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('2', 'fa-file-image-o', '印模中心', '0', '0', 'module.mold', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('20', 'fa-pencil-square-o', '日志管理', '20', '0', 'module.log', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('21', '', '系统操作日志', '21', '20', 'module.log.system', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('22', '', '印章写入key日志', '22', '20', 'module.log.key', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('23', '', '服务端盖章日志', '23', '20', 'module.log.server', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('24', '', '章使用日志', '24', '20', 'module.log.seal', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('3', '', '印模申请', '2', '2', 'module.mold.apply', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('30', 'fa-shield', '证书中心', '30', '0', 'module.certificate', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('31', '', '证书登记', '31', '30', 'module.certificate.register', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('32', '', '证书管理', '32', '30', 'module.certificate.manage', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('4', '', '印模审批', '3', '2', 'module.mold.approval', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('40', 'fa-print', '文档中心', '40', '0', 'module.document', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('41', '', '我的文档', '41', '40', 'module.document.person', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('42', '', '文档管理', '42', '40', 'module.document.manage', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('43', '', '打印设置', '43', '40', 'module.document.print', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('205', '', 'PHP数据导入', '205', '90', 'module.system.dataimport', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('44', '', '文档办理', '44', '40', 'module.document.deal', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('45', '', '我的历史文档', '45', '40', 'module.document.historyPerson', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('46', '', '历史文档管理', '46', '40', 'module.document.historyManage', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('5', '', '印模管理', '4', '2', 'module.mold.manage', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('50', 'fa-key', '设备管理', '50', '0', 'module.device', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('60', 'fa-puzzle-piece', '应用系统管理', '60', '0', 'module.adhibition', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('70', 'fa-file-o', '模板中心', '70', '0', 'module.template', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('71', '', '模板管理', '71', '70', 'module.template.manage', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('72', '', '规则管理', '72', '70', 'module.template.rule', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('73', '', '判定条件', '73', '70', 'module.template.criterion', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('74', '', '通用字典', '74', '70', 'module.template.generalDictionary', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('75', '', '模板功能', '75', '70', 'module.template.function.list', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('80', 'fa-sitemap', '组织机构管理', '80', '0', 'module.organization', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('81', '', '部门管理', '81', '80', 'module.organization.section', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('82', '', '用户管理', '82', '80', 'module.organization.user', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('83', '', '角色管理', '83', '80', 'module.organization.role', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('90', 'fa-th-large', '系统管理', '90', '0', 'module.system', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('91', '', '授权信息', '91', '90', 'module.system.accredit', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('92', '', '权限管理', '92', '90', 'module.system.authority', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('93', '', '菜单管理', '93', '90', 'module.system.menu', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('94', '', '系统字典', '94', '90', 'module.system.dictionary', '1', '1', '1');").executeUpdate();
//			//em.createNativeQuery("INSERT INTO app (id, created_at, status, text1, text2, updated_at, icon, name, order_no, parents_id, route) VALUES ('95', '1489128192', '1', NULL, NULL, '1489128192', 'fa-database', '备份/恢复', '100', '0', 'module.backupAndRecovery');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('96', 'fa-bell', '消息异常管理', '96', '0', 'module.message', '1', '1', '1');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('97', '', '我的消息', '97', '96', 'module.message.mine', '1', '1', '1');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('98', '', '消息列表', '98', '96', 'module.message.list', '1', '1', '1');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('200', 'fa-terminal', '开发实例', '200', '0', 'module.demo', '1', '1', '1');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('201', '', '列表实例', '201', '200', 'module.demo.list', '1', '1', '1');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, icon, name, order_no, parents_id, route, status, created_at, updated_at) VALUES ('202', '', '详情实例', '202', '200', 'module.demo.detail', '1', '1', '1');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, created_at, status, text1, text2, updated_at, icon, name, order_no, parents_id, route) VALUES ('110', '1492590061', '1', NULL, NULL, '1492590061', 'fa-pause-circle-o', '稽核中心', '110', '0', 'module.audit');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO app (id, created_at, status, text1, text2, updated_at, icon, name, order_no, parents_id, route) VALUES ('111', '1492590304', '1', NULL, NULL, '1492590304', NULL, '一级稽核', '111', '110', 'module.audit.first');").executeUpdate();
//			 //em.createNativeQuery("INSERT INTO app (id, created_at, status, text1, text2, updated_at, icon, name, order_no, parents_id, route) VALUES ('112', '1492590362', '1', NULL, NULL, '1492590362', NULL, '二级稽核', '112', '110', 'module.audit.second');").executeUpdate();
//			 log.info("初始化菜单表完成");
//		 }

    //权限初始化
//		 Query rbacOperationnCountQuery=em.createNativeQuery("select count(1) as count from rbac_operation");
//		 rbacOperationnCountQuery.unwrap(SQLQuery.class).setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);
//		 if((((Map)rbacOperationnCountQuery.getSingleResult()).get("count")+"").equals("0")){
//		     log.info("权限表为空。。。。初始化权限表。。。");
//
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('1', 'POST', '/user', 'organization', '添加用户', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('10', 'POST', '/role', 'organization', '添加角色', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('11', 'PUT', '/role', 'organization', '修改角色', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('12', 'DELETE', '/role', 'organization', '删除角色', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('13', 'GET', '/role/', 'organization', '角色查询（单个）', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('14', 'GET', '/role', 'organization', '角色查询（全部角色）', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('15', 'GET', '/roles', 'organization', '角色（高级搜索）', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('16', 'POST', '/operation', 'system', '添加权限', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('17', 'PUT', '/operation', 'system', '修改操作权限', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('18', 'DELETE', '/operation', 'system', '操作权限删除', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('19', 'GET', '/operation/', 'system', '操作权限查询（单个）', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('2', 'DELETE', '/user', 'organization', '删除用户', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('21', 'GET', '/operation', 'system', '查询所有权限', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('22', 'POST', '/department', 'organization', '部门添加', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('23', 'PUT', '/department', 'organization', '部门修改', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('24', 'DELETE', '/department', 'organization', '部门删除', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('26', 'POST', '/app', 'system', '添加菜单', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('27', 'PUT', '/app', 'system', '修改菜单', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('28', 'GET', '/app/', 'system', '查询单个菜单', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('29', 'GET', '/apps', 'system', '查询菜单列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('3', 'PUT', '/user', 'organization', '修改用户', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('30', 'DELETE', '/app', 'system', '删除菜单', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('31', 'GET', '/app', 'system', '查询所有菜单', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('32', 'POST', '/seal_image', 'moulage', '印模申请', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('33', 'DELETE', '/seal_image', 'moulage', '删除印模', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('34', 'PUT', '/seal_image', 'moulage', '印模审批', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('35', 'GET', '/seal_image/', 'moulage', '查询单个印模', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('36', 'GET', '/seal_image', 'moulage', '判断印模名称唯一性', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('37', 'GET', '/seal_image_thumb', 'moulage', '查看印模缩略图', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('38', 'GET', '/seal_images_record', 'moulage', '获取当前用户印模申请记录', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('39', 'GET', '/seal_images_approval', 'moulage', '获取审批列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('4', 'GET', '/users', 'organization', '查询用户（列表）', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('40', 'GET', '/seal_images', 'moulage', '获取印模管理列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('101', 'GET', '/userCollectInfo', 'dashboard', '首页用户展示', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('102', 'GET', '/userSeal/', 'seal', '查看用户印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('103', 'POST', '/seal_image_update', 'moulage', '单个印模修改', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('104', 'GET', '/deptLogSystems', 'other', '部门系统日志', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('105', 'GET', '/myLogSystems', 'other', '我的系统日志', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('106', 'GET', '/deptLogSealUses', 'other', '部门盖章日志', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('107', 'GET', '/myLogSealUses', 'other', '我的盖章日志', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('108', 'GET', '/myLogSealWriteToKeys', 'other', '我的章写入key日志', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('109', 'GET', '/deptLogSealWriteToKeys', 'other', '部门章写入key日志', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('110', 'GET', '/sealCollectInfo', 'dashboard', '首页印章展示', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('111', 'POST', '/new_seal', 'seal', '新建印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('41', 'POST', '/seal', 'seal', '制作印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('42', 'DELETE', '/seal', 'seal', '删除印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('43', 'POST', '/user_seals', 'seal', '印章授权', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('44', 'PUT', '/seal', 'seal', '修改印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('45', 'GET', '/seal', 'seal', '校验印章名称', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('46', 'GET', '/seal/', 'seal', '查询印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('47', 'GET', '/seal_thumb', 'seal', '查看印章缩略图', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('48', 'GET', '/seals', 'seal', '查询印章list', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('49', 'GET', '/my_seals', 'seal', '我的印章', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('5', 'GET', '/user/', 'organization', '查询用户（单个）', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('50', 'GET', '/logSystems', 'log', '查询系统操作日志列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('51', 'GET', '/logServerSeals', 'log', '查询服务端盖章日志列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('52', 'GET', '/logSealWriteToKeys', 'log', '查询印章写入key日志列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('53', 'GET', '/logSealUses', 'log', '查询章使用日志列表', '1', '1', '1');").executeUpdate();
//
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('54', 'GET', '/logPrints', 'print', '查询打印日志列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('55', 'GET', '/logPrint', 'print', '根据文档编号单个查询', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('56', 'POST', '/document', 'print', '添加打印文档', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('57', 'DELETE', '/document', 'print', '根据id删除打印文档', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('58', 'GET', '/document', 'print', '单个查找打印文档', '1', '1', '1');").executeUpdate();
//     		em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('59', 'GET', '/documents', 'print', '分页查询打印文档', '1', '1', '1');").executeUpdate();
//
//     		em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('6', 'GET', '/user/exist', 'organization', '查看登录用户名是否存在', '1', '1', '1');").executeUpdate();
//
//     		em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('60', 'PATCH', '/document', 'print', '打印机的控制', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('61', 'POST', '/document_print_setting', 'print', '添加打印权限设置', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('62', 'GET', '/documents_print_setting', 'print', '分页查询打印权限设置', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('63', 'PUT', '/document_print_setting', 'print', '打印设置详情中的修改打印份数', '1', '1', '1');").executeUpdate();
//
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('64', 'POST', '/cert', 'certificate', '添加证书', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('65', 'DELETE', '/cert', 'certificate', '删除证书', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('66', 'GET', '/certs', 'certificate', '查询证书列表', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('67', 'GET', '/all_certs', 'certificate', '查询所有证书', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('68', 'PUT', '/dictionary', 'system', '修改系统字典配置', '1', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('69', 'GET', '/dictionary', 'system', '查询系统字典列表', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('70', 'POST', '/device', 'device', '添加设备', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('71', 'DELETE', '/device', 'device', '删除设备', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('72', 'PUT', '/device', 'device', '修改设备', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('73', 'GET', '/device/', 'device', '查询设备', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('74', 'GET', '/devices', 'device', '查询设备列表', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('75', 'GET', '/devices_log', 'device', '设备使用日志', '1', '1', '1');").executeUpdate();
////			em.createNativeQuery("INSERT INTOrbac_operation (id, action, controller, module, name, status, created_at, updated_at) VALUES ('76', 'GET', '/cert_name', 'certificate', '校验证书名称', '1', '1', '1');").executeUpdate();
//
//			 log.info("初始化权限表完成");
//		}

//		 //角色初始化
//		Query rbacRoleCountQuery=em.createNativeQuery("select count(1) as count from rbac_role");
//		rbacRoleCountQuery.unwrap(SQLQuery.class).setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);
//		if((((Map)rbacRoleCountQuery.getSingleResult()).get("count")+"").equals("0")){
//		    log.info("角色表为空。。。。初始化角色表。。。");
//		    em.createNativeQuery("INSERT INTO rbac_role (id, approle_role, name, order_by, department_id,status, created_at, updated_at) VALUES ('1', '=1=', '系统管理员', '1',NULL,1,1,1);").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_role (id, approle_role, name, order_by, department_id,status, created_at, updated_at) VALUES ('2', '=1=', '印模审计员', '1', NULL,1,1,1);").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_role (id, approle_role, name, order_by, department_id,status, created_at, updated_at) VALUES ('3', '=', '印模印章管理员', '1',NULL,1,1,1);").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_role (id, approle_role, name, order_by, department_id,status, created_at, updated_at) VALUES ('4', '=', '用户管理员', '0', NULL,1,1,1);").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_role (id, approle_role, name, order_by, department_id,status, created_at, updated_at) VALUES ('5', '=', '日志审计员', '1', NULL,1,1,1);").executeUpdate();
//			em.createNativeQuery("INSERT INTO rbac_role (id, approle_role, name, order_by, department_id,status, created_at, updated_at) VALUES ('6', '=', '盖章用户', '1', NULL,1,1,1);").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '1');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '3');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '2');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '4');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '14');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '101');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '102');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '6');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '5');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '40');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '38');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '32');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '33');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '35');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '36');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '37');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '41');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '43');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '42');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '44');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '45');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '46');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '49');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '48');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '47');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '103');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('2', '34');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('2', '39');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('2', '35');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '110');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('5', '106');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('5', '105');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('5', '109');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('5', '104');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('4', '105');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('2', '105');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '108');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '105');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('6', '107');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('6', '105');").executeUpdate();
//             em.createNativeQuery("INSERT INTO rbac_relation (role_id, operation_id) VALUES ('3', '111');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '2');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '3');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '4');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '5');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '10');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '11');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '12');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '13');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '14');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '20');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '21');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '22');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '23');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '24');").executeUpdate();
//		 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '30');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '31');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '32');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '40');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '41');").executeUpdate();
//			// em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '42');").executeUpdate();
//			em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '43');").executeUpdate();
//			em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '205');").executeUpdate();
//			/* em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '44');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '45');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '46');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '50');").executeUpdate();*/
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '60');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '70');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '71');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '72');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '73');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '74');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '75');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '80');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '81');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '82');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '83');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '90');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '91');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '92');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '93');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '94');").executeUpdate();
//			/* em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '95');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '96');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '97');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '98');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '200');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '201');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '202');").executeUpdate();
//			  em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '110');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '111');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('1', '112');").executeUpdate();
//			 */
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '2');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '3');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '5');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '10');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '11');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '12');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '13');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '20');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '21');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('3', '22');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('5', '20');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('5', '21');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('5', '22');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('5', '24');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('4', '80');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('4', '82');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('4', '20');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('4', '21');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('2', '20');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('2', '21');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('2', '2');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('2', '4');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('6', '20');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('6', '21');").executeUpdate();
//			 em.createNativeQuery("INSERT INTO role_app (role_id, app_id) VALUES ('6', '24');").executeUpdate();
//
//		     log.info("初始化角色表完成");
//		}

//		int time=(int) (System.currentTimeMillis()/1000);
//
//		//用户初始化
//		Query userCountQuery=em.createNativeQuery("select count(1) as count from t_user");
//		userCountQuery.unwrap(SQLQuery.class).setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);
//		//获取数据库方言
//		String s = ((SessionImpl) em.unwrap(org.hibernate.Session.class)).getFactory().getDialect().getClass().getName();
//	    if(s.equals("org.hibernate.dialect.MySQL5Dialect")){
//	        Util.DATABASE_TYPE = "mysql";
//        }else if(s.equals("org.hibernate.dialect.Oracle10gDialect")){
//            Util.DATABASE_TYPE = "oracle";
//        }else if(s.equals("org.hibernate.dialect.SQLServer2008Dialect")){
//            Util.DATABASE_TYPE = "sqlserver";
//        }else{
//            Util.DATABASE_TYPE = "unknown";
//        }
//        log.info(Util.DATABASE_TYPE);

//		if((((Map)userCountQuery.getSingleResult()).get("count")+"").equals("0")){
//		    log.info("用户表为空。。。。初始化用户表。。。");                                                                                                                                                                                                                                                              //  em.createNativeQuery("INSERT INTO USER VALUES ('u1', '1','1461055397', '','','',"+time+",'1','0','344289076@qq.com','1','admin','12678898767','管理员','rVRnZbZSLjod15VmqNuMN9qV5fkd3091uII+UQ==',"+time+",'1',"+time+",'3456789','1');").executeUpdate();
//
//		    em.createNativeQuery("INSERT INTO t_user (id,  birthday,  cert_dn, cert_sn, created_at, created_by, current_role, email, gender, login_id, mobile, name, password, password_updated_at, status, updated_at, work_telephone, department_id,certificate_type,last_read_message_time,client_type) VALUES ('u1', '1461055397', '', '',"+time+", '1', '0', '344289076@qq.com', '1', 'admin', '12678898767', '管理员', '49dc52e6bf2abe5ef6e2bb5b0f1ee2d765b922ae6cc8b95d39dc06c21c848f8c', "+time+", '1',"+time+", '3456789', '0000000000000000000001',0,'"+Util.getTimeStampOfNow()+"',0);").executeUpdate();
//            em.createNativeQuery("INSERT INTO user_role VALUES ('u1', '1');").executeUpdate();
//		    em.createNativeQuery("INSERT INTO manage_department VALUES ('1', '1' ,'0000000000000000000001', '1', 'u1');").executeUpdate();
//
//		    log.info("初始化用户表完成");
//		}

//		//系统字典初始化
//		Query systemDictionaryCountQuery=em.createNativeQuery("select count(1) as count from system_dictionary");
//		systemDictionaryCountQuery.unwrap(SQLQuery.class).setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);
//		if((((Map)systemDictionaryCountQuery.getSingleResult()).get("count")+"").equals("0")){
//			log.info("系统字典表为空。。。。初始化系统字典表。。。");
//
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('1', '1', '1', 'upload_path', 'e:/', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('10', '1', '1', 'defaultLowerLevel', 'true', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('11', '1', '1', 'logLowerLevel', 'false', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('12', '1', '1', 'repeatLogin', 'false', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('13', '1', '1', 'verify_user_cert', '{\"certSn\": \"verify\",\"certDn\": \"verify\"}', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('14', '1', '1', 'printControl', '5;0', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('15', '1', '1', 'verify_captcha', 'true', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('16', '1', '1', 'password_error_times', '10', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('17', '1', '1', 'password_error_num', '5', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('18', '1', '1', 'authority_modules', '[{\"key\":\"dashboard\",\"value\":\"首页\"},{\"key\":\"organization\",\"value\":\"组织机构\"},{\"key\":\"moulage\",\"value\":\"印模中心\"},{\"key\":\"seal\",\"value\":\"印章中心\"},{\"key\":\"template\",\"value\":\"模板中心\"},{\"key\":\"certificate\",\"value\":\"证书中心\"},{\"key\":\"print\",\"value\":\"打印中心\"},{\"key\":\"device\",\"value\":\"设备管理\"},{\"key\":\"adhibition\",\"value\":\"应用系统管理\"},{\"key\":\"log\",\"value\":\"日志管理\"},{\"key\":\"system\",\"value\":\"系统管理\"},{\"key\":\"other\",\"value\":\"其他\"}]', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('19', '1', '1', 'synthetic_type', 'pdf', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('4', '1', '1', 'approve_seal_role', '2,3', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('5', '1', '1', 'update_password_time_out', '100', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('6', '1', '1', 'approle_role', '[{\"id\":\"1\",\"name\":\"印模审批权限\"},{\"id\":\"2\",\"name\":\"模板审批权限\"},{\"id\":\"3\",\"name\":\"印章审批权限\"}]', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('7', '1', '1', 'seal_types', '[{\"v\":\"1\",\"title\":\"公章\"},{\"v\":\"2\",\"title\":\"公章(法人章)\"},{\"v\":\"3\",\"title\":\"公章(合同章)\"},{\"v\":\"4\",\"title\":\"公章(党章)\"},{\"v\":\"5\",\"title\":\"公章(财务章)\"},{\"v\":\"6\",\"title\":\"公章(工会章)\"},{\"v\":\"7\",\"title\":\"个人章\"},{\"v\":\"8\",\"title\":\"个人章(手写签名)\"},{\"v\":\"9\",\"title\":\"个人章(文字签名)\"}]', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('8', '1', '1', 'not_operations', 'POST/api/serviceForMobile/Authentication;GET/api/dictionary;POST/api/updatePw;POST/api/cutLogin;GET/api/departments;GET/api/logout;POST/api/login;GET/api/userInfo;PUT/userInfo;POST/api/serviceForAip/;GET/user/existUserCert;GET/api/getCaptcha;POST/api/verifyCaptcha;GET/api/getProofCode;', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('9', '1', '1', 'not_logins', '/api/serviceForMobile/Authentication;/api/serviceForMobile/getSealList;/api/serviceForMobile/getSealData;/api/loginNoPassword;/api/documentPrintBatch;/api/documentPrintSingle;/api/serviceForAip/;/api/getCaptcha;/api/verifyCaptcha;/api/autoPdfSeal;/api/getProofCode;', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('23', '1', '1', 'passwordStrengthCheck','^([\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*)|([\\\\d\\\\w]*[a-z]+[\\\\d\\\\w]*[A-Z]+[\\\\d\\\\w]*[0-9]+[\\\\d\\\\w]*)$', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('24', '1', '1', 'passwordStrengthNarration', '必须包含大小写字母、数字', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('25', '1', '1', 'passwordLengthMin', '8', '1', '1');").executeUpdate();
//			em.createNativeQuery("INSERT INTO system_dictionary (id, updated_at, allow_update, parameter_key, parameter_value, status, created_at) VALUES ('26', '1', '1', 'passwordLengthMax', '20', '1', '1');").executeUpdate();
//
//			log.info("系统字典表完成");
//		}

}
