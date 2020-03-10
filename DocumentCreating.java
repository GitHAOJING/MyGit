package com.dianju.signatureServer;

import java.io.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.dianju.modules.org.models.Department;
import com.dianju.modules.org.models.DepartmentDao;
import com.dianju.modules.org.models.user.User;
import com.dianju.modules.seal.models.SealDao;
import com.dianju.signatureServer.encryptionDevice.EncryptionDevice;
import org.apache.commons.net.util.Base64;
import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dianju.core.Util;
import com.dianju.core.EncryptionAndDecryption.DES.DesUtil;
import com.dianju.modules.cert.controllers.CertController;
import com.dianju.modules.cert.models.Cert;
import com.dianju.modules.seal.models.Seal;
import com.dianju.modules.templateAIP.models.SealRule;
import com.dianju.modules.templateAIP.models.TemplateAIP;
import com.dianju.signatureServer.DocumentComposition.SyntheticPattern;
import com.dianju.signatureServer.cache.Cache;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import srvSeal.SrvSealUtil;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

/**
 * 文档合成
 * @author liuchao
 */
public class DocumentCreating {

	private final Logger log = LoggerFactory.getLogger(this.getClass());

    ExecutorService documentToImgThread = Executors.newCachedThreadPool();

    @Autowired
    private DJPdfToImgUtil djPdfToImgUtil;
	
	public void init(){
		if(srvSealUtil==null){
  			srvSealUtil=(SrvSealUtil)Util.getBean("srvSealUtil");

  		}
		if(path==null){
			qifenCount=Integer.parseInt(Util.getSystemDictionary("qifencount"));
			path=Util.getSystemDictionary("upload_path");
			templateSynthesisPath= path+"/templateSynthesis";
			sealFilePath=path+"/sealFilePath";
			syntheticType= Util.getSystemDictionary("synthetic_type");
		}
	}
	int openObj(String openPath, int nFS1, int nFS2) {
		log.info("openObj参数openPath----------"+openPath);
		log.info("openObj参数nFS1---------"+nFS1);
		log.info("openObj参数nFS2---------"+nFS2);
		init();
		if (System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1) {
			return srvSealUtil.openObj(openPath, nFS1, nFS2);
		} else {
			return srvSealUtil.openObj(openPath, nFS1);
		}
	}

	/**
	 *
	 * @param nObjID objid
	 * @param savePath 保存路径
	 * @param saveType 保存文件类型
	 * @param keepObj 1不关闭文档0关闭
	 * @return
	 */
	int saveFile(int nObjID, String savePath, String saveType,int keepObj){
		if (System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1) {
			return srvSealUtil.saveFile(nObjID, savePath, saveType, keepObj);
		} else {
			if(keepObj==1)
				return srvSealUtil.saveFileEx(nObjID, savePath, 0);
			else
				return srvSealUtil.saveFile(nObjID, "");
		}
	}


	/**
	 * aip登录
	 *
	 * @param nObjID 对象ID，可由openObj方法获取
	 * @param nLoginType 登录类型
	 * @param userID 用户名
	 * @param pwd 密码
	 * @return 0为成功，1为失败
	 */
	int login(int nObjID, int nLoginType, String userID,String pwd){
		init();//初始化控件
		if (System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1) {
			return srvSealUtil.login(nObjID, nLoginType, userID, pwd);
		}else{
			//if(nLoginType==2) {
//			int loginRet= srvSealUtil.login(nObjID, "HWSEALDEMOXX",4,   "DEMO");
			int loginRet= srvSealUtil.login(nObjID, userID,2,   "DEMO");
			if(loginRet==1){
				return 0;
			}else {
				return 1;
			}
		}
	}

    //Aip打开文档字节流
    int openData(byte[] fileData){
        init();//初始化控件
        return srvSealUtil.openData(fileData);
    }

	/**
	 * 数据模板合成、文档追加合成
	 * @param nObjID 对象ID，可由openObj方法获取
	 * @param tempPath  模板路径或文档路径
	 * @param docData “STRDATA:”+业务数据或“”
	 * @return 1为成功，0为失败
	 */
	int addPage(int nObjID, String tempPath, String docData,String  beginTime,SyntheticMode ... syntheticMode) {
		if (System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1) {
			return srvSealUtil.addPage(nObjID,tempPath,docData);
		}else{
			String linuxFonts=Util.getSystemDictionary("linuxFonts");
			int setFont=srvSealUtil.setValue(0, "SET_FONTFILES_PATH", linuxFonts);//自定义设置linux字体库位置
			log.info("setFont:"+setFont);

			if(syntheticMode.length!=0&&syntheticMode[0]==SyntheticMode.alone){
				String fname=new Date().getTime()+"";
				fname=	beginTime+"-"+fname;
				String savePath=templateSynthesisPath+ "/"+fname+".pdf";
				int aloneMergeFileRet= aloneMergeFile(tempPath,docData,savePath,fname);
				if(aloneMergeFileRet==0){
					return 0;
				}else{
					return srvSealUtil.mergeFile(nObjID,savePath,srvSealUtil.getPageCount(nObjID));
				}
			}else{
				int mergeFileRet=srvSealUtil.mergeFile(nObjID,tempPath,srvSealUtil.getPageCount(nObjID));
				log.info("mergeFileRet:"+mergeFileRet);
				if(mergeFileRet==1){
					if(docData!=null&&!"".equals(docData)) {
						int setValueRet = srvSealUtil.setValue(nObjID, "FORM_DATA_TXT_FORMAT", docData);
						log.info("setValueRet:" + setValueRet);
						if (setValueRet == 1) {
							return 1;
						} else {
							return 0;
						}
					}else{
						return 1;
					}
				}else{
					return 0;
				}
			}
		}
	}

	/**
	 * 模板合成（创建新文档形式）
	 * @param tempDate aip模板base64
	 * @param docData aip节点数据
	 * @param saveUrl 保存路径
	 * @param beginTime
	 * @return 1成功0失败
	 */
	int aloneMergeFile(String tempDate,String docData,String saveUrl,String beginTime){
		int nObjID1 = openObj("", 0, 0);
		log.info("nObjID1:"+nObjID1);
		if(nObjID1<=0){
			log.info("服务器繁忙，请稍后重试6");
			return 0;
		}
		try{
			int l = login(nObjID1, 2,"HWSEALDEMOXX","");
			log.info("login:" + l);
			int mergeFileRet=srvSealUtil.mergeFile(nObjID1,tempDate,srvSealUtil.getPageCount(nObjID1));
			log.info("mergeFileRet:"+mergeFileRet);
			if(mergeFileRet==1){
				if(docData!=null&&!"".equals(docData)) {
					int setValueRet = srvSealUtil.setValue(nObjID1, "FORM_DATA_TXT_FORMAT", docData);
					log.info("setValueRet:" + setValueRet);
					if (setValueRet == 1) {
						int saveFileRet=saveFile(nObjID1, saveUrl, syntheticType, 1);
						if(saveFileRet==0){
							log.info(beginTime+":aloneMergeFile文档保存失败，请检查服务器，保存路径："+saveUrl);
							return 0;
						}else {
							log.info(beginTime + ":aloneMergeFile文档保存成功" + new Date() + "保存路径：" + saveUrl);
							return 1;
						}
					} else {
						return 0;
					}
				}else{
					int saveFileRet=saveFile(nObjID1, saveUrl, syntheticType, 1);
					if(saveFileRet==0){
						log.info(beginTime+":aloneMergeFile文档保存失败，请检查服务器，保存路径："+saveUrl);
						return 0;
					}else{
						log.info(beginTime+":aloneMergeFile文档保存成功"+new Date()+"保存路径："+saveUrl);
						return 1;
					}

				}
			}else{
				return 0;
			}
		}catch (Exception e){
			e.printStackTrace();
			return 0;
		}finally {
			log.info(beginTime+":aloneMergeFile文档关闭");
			saveFile(nObjID1, "", syntheticType, 0);
		}
	}


	/**
	 * 文档合并
	 * @param nObjID
	 * @param FILE_LIST
	 * @param downFileMap
	 * @param beginTime
	 * @return ok成功 其他失败原因
	 */
     String makeMergerFile(int nObjID,Element FILE_LIST,Map downFileMap,String beginTime){
    		init();
    		List<Element> TREE_NODES=FILE_LIST.elements("TREE_NODE");
        	log.info(beginTime+":文档合并开始："+new Date());
        	for(int i=0;i<TREE_NODES.size();i++){
        		Element TREE_NODE=TREE_NODES.get(i);
        		String CJ_TYPE=TREE_NODE.elementText("CJ_TYPE");
        		Element APP_DATA =TREE_NODE.element("APP_DATA");
        		String MODEL_NAME= TREE_NODE.elementText("MODEL_NAME");
        		if("file".equalsIgnoreCase(CJ_TYPE)){
        			Map	fileMsg=(Map)downFileMap.get(i);
        			String fileUrl=fileMsg.get("FILE_MSG")+"";
        			String fileNo=fileMsg.get("FILE_NO")+"";
        			log.info(beginTime+":"+fileUrl);
        			int addPageRet=addPage(nObjID, fileUrl,"",beginTime);
        			log.info(beginTime+":addPage:"+addPageRet);
        			if(addPageRet!=1){
        				log.info(beginTime+":添加文档"+i+" "+fileNo+"时失败");
        				return "添加文档"+i+"时失败";
        			}
    			}else if("data".equalsIgnoreCase(CJ_TYPE)){
        			TemplateAIP templateAip=Cache.getTemplateAipByName(MODEL_NAME);
        			if(templateAip==null){
        				log.info(beginTime+":模板不存在，模板名："+MODEL_NAME);
        				return "模板不存在，模板名："+MODEL_NAME;
        			}
        		    int addPageRet=addPage(nObjID, "STRDATA:"+templateAip.getContentData(), xmlToAipData(APP_DATA),beginTime,SyntheticMode.alone);
        			log.info(beginTime+":addPage:"+addPageRet);
        			if(addPageRet!=1){
        				log.info(beginTime+":添加文档"+i+"时失败");
        				return "添加文档"+i+"时失败";
        			}
        		}else if("base64".equalsIgnoreCase(CJ_TYPE)){
        			int addPageRet=addPage(nObjID, "STRDATA:"+MODEL_NAME, xmlToAipData(APP_DATA),beginTime);
         			log.info(beginTime+":addPage:"+addPageRet);
         			if(addPageRet!=1){
         				log.info(beginTime+":添加文档"+i+"时失败");
         				return "添加文档"+i+"时失败";
         			}
        		}
        	}
        	log.info(beginTime+":文档合并结束："+new Date());
        	return "ok";




    }
   /**
    * 模板合成xml转换aip数据
    * @param APP_DATA xml节点
    * @return STRDATA:name=张三\r\nsex=男.... 无节点返回""
    */
    public static String xmlToAipData(Element APP_DATA){
    	if(APP_DATA!=null){
    		String ret="STRDATA:";
	    	List<Element> APP_DATAs= APP_DATA.elements();
			Map tempmap= new HashMap<String,Integer>();
	    	for(Element e:APP_DATAs){
				if(tempmap.get(e.getName())!=null){
					int numFlag = (int) tempmap.get(e.getName());
					if(numFlag==0){
						ret+="&"+e.getName()+"="+e.getText()+"\r\n";
						tempmap.put(e.getName(), numFlag+1);
					}else{
						ret+="&"+e.getName()+numFlag+"="+e.getText()+"\r\n";
						tempmap.put(e.getName(), numFlag+1);
					}
				}else{
					ret+=e.getName()+"="+e.getText()+"\r\n";
					tempmap.put(e.getName(), 0);
				}
	    	}
	    	if(ret.equals("STRDATA:"))
	    		return "";
	    	else
	    		return ret;
    	}else{
    		return "";
    	}
    }
   /**
    * 插入二位码
    * @param nObjID 文档id
    * @param CodeBarXml 二维码报文 合并文档 META_DATA 不合并文档TREE_NODE
    * @return ok成功 其他失败原因
    */
    String insertCodeBar(int nObjID,Element CodeBarXml,String beginTime){
    	String IS_CODEBAR=CodeBarXml.elementText("IS_CODEBAR");
    	if("true".equalsIgnoreCase(IS_CODEBAR)){
    		log.info(beginTime+":插入二维码开始");
    		String CODEBAR_TYPE =CodeBarXml.elementText("CODEBAR_TYPE");//二维码类型1:p417,0:QR
    		String CODEBAR_DATA =CodeBarXml.elementText("CODEBAR_DATA");// 二维码信息
    		String CODEBAR_PAGE =CodeBarXml.elementText("CODEBAR_PAGE");// 插入二维码页
    		String X_COORDINATE =CodeBarXml.elementText("X_COORDINATE");// 偏移量左右
    		String Y_COORDINATE =CodeBarXml.elementText("Y_COORDINATE");// 偏移量上下
    		log.info(beginTime+":CODEBAR_TYPE:"+CODEBAR_TYPE+" X_COORDINATE:"+X_COORDINATE+" Y_COORDINATE:"+Y_COORDINATE+" CODEBAR_DATA:"+CODEBAR_DATA+" CODEBARPAGE:"+CODEBAR_PAGE);
    		String	insertCodeBarret=insertCodeBar(nObjID,CODEBAR_TYPE,CODEBAR_PAGE, X_COORDINATE, Y_COORDINATE, CODEBAR_DATA ,beginTime);
			if(!"ok".equals(insertCodeBarret)){
				return insertCodeBarret;
			}else return "ok";

    	}else return "ok";

    }

    /**
     * 插入二位码（本类使用）
     * @param nObjID 文档id
     * @param codeBarType 二维码类型1:p417,0:QR
     * @param codeBarPage 二维码加盖页码1,2,3,-1是最后一页 -2第1页 0是所有页
     * @param x_coordinate 横坐标
     * @param y_coordinate 纵坐标
     * @param coderData 二维码数据
     * @param beginTime
     * @return ok成功 其他失败原因
     */
    private  String insertCodeBar(int nObjID,String codeBarType,String codeBarPage, String x_coordinate, String y_coordinate,String coderData ,String beginTime){
    	String codeBarTypeStr="";
    	int insertPictureRet=1;
		int codebarScaling=Integer.parseInt(Util.getSystemDictionary("codebarScaling"));
    	if("1".equals(codeBarType)){
    		codeBarTypeStr="BARCODEDATA:";
    	}else if("0".equals(codeBarType)){
			if (System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") == -1){
				codeBarTypeStr="BARCODEUTF8DATA:";
				codebarScaling+=13107200;
			}else{
				codeBarTypeStr="QRBARDATA:";
				coderData="  "+coderData;//控件bug 少两个字符
			}
		}else{
    		log.info(beginTime+":CODEBAR_TYPE参数错误");
    		return "CODEBAR_TYPE参数错误";
    	}
    	int x=0;
    	int y=0;
    	try {
    		x=Integer.parseInt(x_coordinate);
        	y=Integer.parseInt(y_coordinate);
		} catch (Exception e) {
			log.info(beginTime+":X_COORDINATE或Y_COORDINATE参数错误X_COORDINATE:"+x_coordinate+" Y_COORDINATE:"+y_coordinate+" CODEBARPAGE:"+codeBarPage);
			return "X_COORDINATE或Y_COORDINATE参数错误X_COORDINATE:"+x_coordinate+" Y_COORDINATE:"+y_coordinate;
		}

        log.info("coderData----"+coderData);
        log.info("coderData22222----"+(codeBarTypeStr+coderData));

        if("-2".equals(codeBarPage)){
    		insertPictureRet=srvSealUtil.insertPicture(nObjID, codeBarTypeStr+coderData,0, x, y, codebarScaling);
    	}else if("-1".equals(codeBarPage)){
    		int pageCount=srvSealUtil.getPageCount(nObjID);
    		insertPictureRet=srvSealUtil.insertPicture(nObjID, codeBarTypeStr+coderData, pageCount-1, x, y, codebarScaling);
    	}else if("0".equals(codeBarPage)){
    		int pageCount=srvSealUtil.getPageCount(nObjID);
    		for(int i=0;i<pageCount;i++){
    			int b=srvSealUtil.insertPicture(nObjID, codeBarTypeStr+coderData, i, x, y, codebarScaling);
    			if(b!=1){
    				insertPictureRet=-1;
    				break;
    			}
    		}
    	}else{
    		String[] codeBarPages= codeBarPage.split(",");
    		for(int i=0;i<codeBarPages.length;i++){
    			try {
    				int page=Integer.parseInt(codeBarPages[i])-1;
    				int b=srvSealUtil.insertPicture(nObjID, codeBarTypeStr+coderData, page, x, y,codebarScaling);
        			if(b!=1){
        				insertPictureRet=-1;
        				break;
        			}
				} catch (NumberFormatException e) {
					log.info(beginTime+":插入二维码失败，非法的页码:"+codeBarPages[i]);
					return "插入二维码失败，非法的页码:"+codeBarPages[i];
				}

    		}
    	}
    	if (insertPictureRet != 1) {
			log.info(beginTime+":插入二维码失败，请检查页码是否存在，ocx返回值：" + insertPictureRet);
			return "插入二维码失败，请检查页码是否存在，ocx返回值：" + insertPictureRet;
		}
		log.info(beginTime+":加盖二维码成功");
		return "ok";
    }
    /**
     * java签名暂时不支持多证书故取第一个规则证书

     * @param SealXml
     * @param beginTime
     * @return ok成功 其他失败原因
     */
    String addSeal(String savePath,SyntheticPattern syntheticPattern,Element SealXml,String beginTime) throws Exception {
    	String saveSealFilePath=sealFilePath+"/";
		String FILE_NO=SealXml.elementText("FILE_NO");
		saveSealFilePath +=FILE_NO;
    	if(SyntheticPattern.AddSeal==syntheticPattern){
	    	log.info(beginTime+":开始加盖印章");
	    	String RULE_TYPE=SealXml.elementText("RULE_TYPE");
	    	String AREA_SEAL=SealXml.elementText("AREA_SEAL");
	    	String areaDatastr="";
	    	Cert cert=null;
	    	Cert sm2Cert=null;
			byte[] savebs=null;


	    	if("0".equals(RULE_TYPE)){//规则合成
	    		String RULE_NO=SealXml.elementText("RULE_NO");
				String SEALUSER_NAME=SealXml.elementText("SEALUSER_NAME");
	    		if("".equals(RULE_NO)){//不盖章
	    			return "RULE_NO不可为空";
	    		}else{
	    			String[] ruleNos= RULE_NO.split(",");
	    			/**begin临时代码  **/
	        		String	certId=null;
	        		String sm2CertId=null;
	        		/**end临时代码  **/
	        		int nObjID=-1;
	    			for(int i=0;i<ruleNos.length;i++){
	    				if(savebs==null)
							nObjID =openObj(savePath, 0, 0);
	    				else
							srvSealUtil.openData(savebs);
						log.info(beginTime + ":nObjID:" + nObjID);
						if (nObjID <= 0) {
							log.info(beginTime + ":服务器繁忙，请稍后重试4");
							throw new Exception("服务器繁忙，请稍后重试4");
						}
						try {
							String useId = "HWSEALDEMOXX";
							if (SEALUSER_NAME != null && SEALUSER_NAME != "") {
								useId = SEALUSER_NAME;
							}

							int l =login(nObjID, 2, useId, "");
							log.info(beginTime + ":login:" + l);
							int	sealModeRet=srvSealUtil.setSealMode(nObjID, 1);
							log.info(beginTime+":sealModeRet:"+sealModeRet);
							SealRule sealRule=Cache.getSealRuleByNumber(ruleNos[i]);
							if(sealRule==null){
								log.info(beginTime+":RULE_NO不存在RULE_NO:"+ruleNos[i]);
								return "RULE_NO不存在RULE_NO:"+ruleNos[i];
							}else{
								certId=sealRule.getCertId();
								sm2CertId=sealRule.getSm2CertId();
								Seal seal=Cache.getSealById(sealRule.getSealId());
								if(seal==null){
									return "印章不存在："+sealRule.getSealId();
								}

								//查询用户是否具有使用印章权限
								if (!(SEALUSER_NAME == null || "".equals(SEALUSER_NAME))) {
									boolean checkSealUser = checkSealUser(seal, SEALUSER_NAME);
									if(!checkSealUser){
										log.info(beginTime + ":RULE_NO对应的印章该用户未经授权；用户名:" + SEALUSER_NAME);
										return "RULE_NO对应的印章该用户未经授权；用户名:" + SEALUSER_NAME;
									}
								}


								String sealData=seal.getData();
								String	pagesData="";

								try {
									pagesData=getPagesDataStr(nObjID, sealRule,SealXml);
								} catch (Exception e) {
									e.printStackTrace();
									log.info(beginTime+":规则解析错误");
									return "规则解析错误";
								}



								srvSealUtil.setValue(nObjID,"SET_P7SIGN_BYTELEN", "8192");
								cert=Cache.getCertById(certId);
								if(	"2".equals(Util.getSystemDictionary("signatureType"))){//双签模式加载sm2证书
									sm2Cert=Cache.getCertById(sm2CertId);
									if(sm2Cert==null){
										return "证书不存在SM2："+certId;
									}
									String sm2dn=sm2Cert.getDn();
									log.info(beginTime+":sm2Dn:"+sm2dn);
									int sm2Dn=srvSealUtil.setValue(nObjID, "SET_JMJSERVER_GMCERTDN", sm2dn);
									log.info(beginTime+":sm2DnRet:"+sm2Dn);
									String sm2Path=Cache.certPath+"/"+sm2Cert.getId()+".cer";
									int sm2path=srvSealUtil.setValue(nObjID, "SET_JMJSERVER_GMCERTPATH", Cache.certPath+"/"+sm2Cert.getId()+".cer");
									log.info(beginTime+":sm2path:"+sm2path);
								}
								if(cert==null){
									return "证书不存在RSA："+certId;
								}

								if(sealRule.getType()==3||sealRule.getType()==7){//骑缝章
									String [] pagesDatas=pagesData.split("=");
									for(int j=0;j<pagesDatas.length;j++){
										log.info(pagesDatas[j]);
										int addSealret =srvSealUtil.addSeal(nObjID, pagesDatas[j]+sealData, "", "AUTO_ADD_SEAL_FROM_PATH");
										if(addSealret!=1){
											log.info(beginTime+":盖章失败addSeal:"+addSealret);
											return "盖章失败addSeal:"+addSealret;
										}
										savebs=sign (nObjID, sm2Cert, cert, beginTime);
										if(savebs==null||savebs.length==0){
											log.info(beginTime+":签名失败");
											return "签名失败";
										}
									}
								}else{
									int addSealret =srvSealUtil.addSeal(nObjID, pagesData+sealData, "", "AUTO_ADD_SEAL_FROM_PATH");
									if(addSealret!=1){
										log.info(beginTime+":盖章失败addSeal:"+addSealret);
										return "盖章失败addSeal:"+addSealret;
									}
									savebs=sign (nObjID, sm2Cert, cert, beginTime);
									if(savebs==null||savebs.length==0){
										log.info(beginTime+":签名失败");
										return "签名失败";
									}



								}

							}
						} catch (Exception e) {
							throw e;
						} finally {
							log.info("SealFile文档关闭");
							saveFile(nObjID, "", syntheticType, 0);
						}




	    			}


	    		}
	    	}else if("1".equals(RULE_TYPE)){//信息合成
	    		String RULE_INFO=SealXml.elementText("RULE_INFO");
	    		String CERT_NAME=SealXml.elementText("CERT_NAME");
	        	String SEAL_NAME=SealXml.elementText("SEAL_NAME");
	        	String DEPT_CODE = SealXml.elementText("DEPT_CODE");
	        	Seal seal = new Seal();
	        	if (null != SealXml.element("DEPT_CODE") && !(DEPT_CODE.equals(""))){//存在单位区划码
					Department department = departmentDao.findByServerLabel(DEPT_CODE);
					if (null == department){
						return "单位不存在："+DEPT_CODE;
					}
					List<Seal> sealList = sealDao.findByDepartmentId(department.getId());
					if(1 > sealList.size()){
						return "单位不存在印章："+DEPT_CODE;
					}
					seal = sealList.get(0);
				}else{
	        		if(null != SealXml.element("SEAL_NAME") && !(SEAL_NAME.equals(""))){//存在印章名称
						seal = Cache.getSealByName(SEAL_NAME);
					}else{
	        			return "参数SEAL_NAME、DEPT_CODE不能同时为空";
					}
				}
	        	if(null == seal){
        			return "印章不存在："+SEAL_NAME;
        		}
				int nObjID =openObj(savePath, 0, 0);
				log.info(beginTime + ":nObjID:" + nObjID);
				if (nObjID <= 0) {
					log.info(beginTime + ":服务器繁忙，请稍后重试4");
					throw new Exception("服务器繁忙，请稍后重试4");
				}
				try {
					int l =login(nObjID, 2, "HWSEALDEMOXX", "");
					log.info(beginTime + ":login:" + l);
					int	sealModeRet=srvSealUtil.setSealMode(nObjID, 1);
					log.info(beginTime+":sealModeRet:"+sealModeRet);
					srvSealUtil.setValue(nObjID,"SET_P7SIGN_BYTELEN", "8192");
					int addSealret =srvSealUtil.addSeal(nObjID, RULE_INFO+seal.getData(), "", "AUTO_ADD_SEAL_FROM_PATH");
					if(addSealret!=1){
						log.info(beginTime+":盖章失败addSeal:"+addSealret);
						return "盖章失败addSeal:"+addSealret;
					}
					cert=Cache.getCertByName(CERT_NAME);
					if(cert==null){
						return "证书不存在："+CERT_NAME;
					}
					savebs=sign(nObjID, sm2Cert, cert, beginTime);

					if(savebs==null||savebs.length==0){
						log.info(beginTime+":签名失败");
						return "签名失败";
					}
				} catch (Exception e) {
					throw e;
				} finally {
					log.info("SealFile文档关闭");
					saveFile(nObjID, "", syntheticType, 0);
				}
	        }else{
	    		log.info(beginTime+"RULE_TYPE错误RULE_TYPE:"+RULE_TYPE);
	    		return "RULE_TYPE错误RULE_TYPE:"+RULE_TYPE;
	    	}





    		OutputStream o=null;

    		deleteFile(saveSealFilePath);
    		try {
			    o=new FileOutputStream(new File(saveSealFilePath));
				o.write(savebs);
				o.flush();
			} catch (Exception e) {
				e.printStackTrace();
				log.info(beginTime+":SealFile文档保存失败，请检查服务器，保存路径："+saveSealFilePath);
				return "SealFile文档保存失败，请检查服务器，保存路径："+saveSealFilePath;
			}finally {
				try {
					savebs=null;
					o.close();
				} catch (Exception e) {
				}
			}
    		log.info(beginTime+":SealFile文档保存成功，保存路径："+saveSealFilePath);
    		return "ok";
		}else {
    		log.info(beginTime+":文档不盖章");
    		deleteFile(saveSealFilePath);
			int nObjID =openObj(savePath, 0, 0);
			log.info(beginTime + ":nObjID:" + nObjID);
			if (nObjID <= 0) {
				log.info(beginTime + ":服务器繁忙，请稍后重试4");
				throw new Exception("服务器繁忙，请稍后重试4");
			}
			try {
				int l =login(nObjID, 2, "HWSEALDEMOXX", "");
				log.info(beginTime + ":login:" + l);

				int saveFileRet =saveFile(nObjID,saveSealFilePath, syntheticType, 1);
    			log.info(beginTime+":saveFile:"+saveFileRet);
				if(saveFileRet==0){
					log.info(beginTime+":saveFile文档保存失败，请检查服务器，保存路径："+saveSealFilePath);
					return "saveFile文档保存失败";
				}else{
					log.info(beginTime+":saveFile文档保存成功"+new Date()+"保存路径："+saveSealFilePath);
				}
			} catch (Exception e) {
				throw e;
			} finally {
				log.info("SealFile文档关闭");
				saveFile(nObjID, "", syntheticType, 0);
			}
    	}
    	return "ok";
    }

	/**
	 * 查询所传用户登录id是否具有使用印章的权限
	 * @param seal
	 * @param sealuser_name
	 * @return
	 */
	private boolean checkSealUser(Seal seal, String sealuser_name) {

		boolean sealUserCheck = false;

		Set<User> userSeal1 = seal.getUserSeal();
		for (User user : userSeal1) {
			if (user.getLoginId() == sealuser_name || user.getLoginId().equals(sealuser_name)) {
				sealUserCheck = true;
			}
		}
		return sealUserCheck;
	}


	private byte[] sign (int nObjID,Cert sm2Cert,Cert cert ,String beginTime){
		byte[] savebs=null;
		 log.info(beginTime+"：签名开始");
		 EncryptionDevice encryptionDevice=null;
		 try {
			 encryptionDevice=(EncryptionDevice)Util.getBean(Util.getSystemDictionary("encryptionDeviceImpl"));
		 } catch (Exception e) {
			 log.info(beginTime+"未找到签名实现:");
			// return "未找到签名实现:";
		 }
		 if("2".equals(Util.getSystemDictionary("signatureType"))){//双签模式加载sm2签名)
			 String sm2Data=srvSealUtil.getValueEx(nObjID,"GET_AIPSIGN_ORIDATA", 0, "", 0, "");
			 log.info(beginTime+":sm2Data:"+sm2Data);
			 byte[] sm2SignData =encryptionDevice.getSM2SignData(sm2Cert,Base64.decodeBase64(sm2Data));
			 if(sm2SignData==null||sm2SignData.length==0){
				 log.info(beginTime+":sm2加密机返回错误");
			//	 return "sm2加密机返回错误";
			 }
			 int set1=srvSealUtil.setValueEx(nObjID,"SET_AIPSIGN_ORIDATA",0, 0,Base64.encodeBase64String(sm2SignData));
			 System.out.println(beginTime+":set:" + set1);
		 }

		 byte[] pdfbs = srvSealUtil.getData(nObjID);
		 byte[] data = srvSealUtil.getSignSHAData(nObjID);
		 int pos = srvSealUtil.getSignPos(nObjID);
		 if(0==cert.getType()){//服务器证书rsa
			 String pwd="";
			 try {
				 DesUtil des = new DesUtil(CertController.DESPASSWORD);
				 pwd=des.decrypt(cert.getPwd());
			 } catch (Exception e) {
				 log.info(beginTime+":证书密码解析失败：证书名："+cert.getName()+ " 密码："+cert.getPwd());
			//	 return "异常-cert-password";
			 }
			 KeyStore keyStore;
			 byte[] signedData=null;
			 try {
				 keyStore = SignUtil.getKeyStore(cert.getPfxContent(), pwd);
				 signedData=SignUtil.signP7Bytes(data, keyStore, pwd);
				 if(signedData==null||signedData.length==0){
					 throw new Exception(beginTime+":数字签名失败0");
				 }
				 savebs = chgBs(pdfbs, pos, signedData);
				 if(savebs==null||savebs.length==0){
					 throw new Exception(beginTime+":数字签名失败1");
				 }
			 } catch (Exception e) {
				 log.info(beginTime+":数字签名失败"+e.getMessage());
				 e.printStackTrace();
			//	 return "数字签名失败"+e.getMessage();
			 }
		 }else{//加密机rsa
			 byte [] signedData =encryptionDevice.getRSASignData(cert,data);
			 String p7data = null;
			 try {
				 p7data = getP7FromP1(Cache.certPath+""+cert.getId()+".cer", signedData ,data );
				 savebs = chgBs(pdfbs, pos, Base64.decodeBase64(p7data));
			 } catch (Exception e) {
				 log.info(beginTime+":RSA P7签名失败"+e.getMessage());
				 e.printStackTrace();
			//	 return "RSA P7签名失败";
			 }
		 }
		 log.info(beginTime+"：签名成功");
		return savebs;
		//return "ok";
	}
	/**
	 * 拼接盖章数据 addSeal用
	 * @param nObjID
	 * @param sealRule
	 * @param SealXml
	 * @return
	 * @throws JsonParseException
	 * @throws JsonMappingException
	 * @throws IOException
	 */
    private String getPagesDataStr(int nObjID,SealRule sealRule,Element SealXml) throws JsonParseException, JsonMappingException, IOException{
    	String pagesData="";
    	ObjectMapper mapper=new ObjectMapper();
    	Map<String,Object> map = mapper.readValue(sealRule.getParameterDescription(), HashMap.class);
    	 int pageCount=	srvSealUtil.getPageCount(nObjID);
    	if(sealRule.getType()==1){//绝对坐标
    		 int sealPage=pageNumberConversion( (Integer)map.get("sealPage"),pageCount);
    		 int verticalDistance= (Integer)map.get("verticalDistance");
    		 int horizontalDistance= (Integer)map.get("horizontalDistance");
    		 pagesData=sealPage+","+horizontalDistance+",5,5,"+verticalDistance+",";

    	}else if (sealRule.getType()==2){//书签

    	}else if (sealRule.getType()==3||sealRule.getType()==7){//骑缝章、多页骑缝
    		/*int documentType=(Integer)map.get("documentType");
    		int qifengType=(Integer)map.get("qifengType");
    		int position=(Integer)map.get("position");
    		int beginPage=pageNumberConversion((Integer)map.get("beginPage"),pageCount);
    		int endPage=pageNumberConversion((Integer)map.get("endPage"),pageCount);
    		*//**计算隔页方式**//*
    		int intervalPage=1;//单页模式每页盖章
    		if(sealRule.getType()==7){//多页骑缝
    			int pageNum=(Integer)map.get("pageNum");
    			intervalPage=pageNum;
    		}else{
    			if(documentType==1){//双面模式 隔页盖章
        			intervalPage=2;
        		}
    		}

    		*//********************************//*
    		*//**计算骑缝需要多少个章**//*
    		int sealPageCount=(endPage-beginPage)/intervalPage;
    		int countSeal=sealPageCount/qifenCount;
    		if(sealPageCount%qifenCount!=0)countSeal++;

    		*//*******************************//*

    		String basePagesData=","+position+",5,"+qifengType+",50,";
    		for(int i=0;i<countSeal;i++){
    			String strPages="";
    			//int thisPage=0;
    			if(intervalPage==1){
	    			for(int j=0;j<qifenCount;j++){
	    				strPages+=j+",";
	    				//thisPage=thisPage+intervalPage;
	    			}
    			}else{
    				for(int j=1;j<qifenCount;j++){
	    				strPages+=j*intervalPage+",";
	    				//thisPage=thisPage+intervalPage;
	    			}
    			}
    			//strPages=strPages.substring(1)+",";
    			pagesData+="="+qifenCount*i+basePagesData+strPages;
    			strPages="";
    		}
    		log.info(pagesData);
    		pagesData=pagesData.substring(1);*/
    		int documentType = (Integer) map.get("documentType");
            int qifengType = (Integer) map.get("qifengType");
            int position = (Integer) map.get("position");
            int beginPage = pageNumberConversion((Integer) map.get("beginPage"), pageCount);
            int endPage = pageNumberConversion((Integer) map.get("endPage"), pageCount);
            /**隔页方式**/
            int intervalPage = 1;//单面模式 每页盖章
            if (documentType == 1) {//双面模式 隔页盖章
                intervalPage = 2;
            }
            /**盖章数量**/
            int countSeal = 1;//骑缝章 只盖一个章
            int pageNum = (endPage - beginPage) / intervalPage + 1;
            if (sealRule.getType() == 7) {//多页骑缝 计算需要多少个章
                pageNum = (Integer) map.get("pageNum");
                countSeal = (endPage - beginPage + 1) / (pageNum * intervalPage);
                if ((endPage - beginPage + 1) % (pageNum * intervalPage) != 0) {
                    countSeal++;
                }
            }
            String basePagesData = "," + position + ",5," + qifengType + "," + (100/pageNum) + ",";
            for (int i = 0; i < countSeal; i++) {
                String strPages = "";
                for (int j = 1; j < pageNum; j++) {
                    strPages += j * intervalPage + ",";
                }
                pagesData += "=" + beginPage + basePagesData + strPages;
                beginPage += (pageNum * intervalPage);
            }
            pagesData = pagesData.substring(1);
    		
    	}if (sealRule.getType()==4){//文字(覆盖)
    		String matchingText=(String)map.get("matchingText");
    		int verticalOffset=(Integer)map.get("verticalOffset");
    		int horizontalOffset=(Integer)map.get("horizontalOffset");
    		int beginPage=pageNumberConversion((Integer)map.get("beginPage"),pageCount);
    		int endPage=pageNumberConversion((Integer)map.get("endPage"),pageCount);
    		pagesData="AUTO_ADD:"+beginPage+","+endPage+","+horizontalOffset+","+verticalOffset+","+255+","+matchingText+")|(4,";
    	}else if(sealRule.getType()==5){//文字(之后)
    		String matchingText=(String)map.get("matchingText");
    		int horizontalOffset=(Integer)map.get("horizontalOffset");
    		int beginPage=pageNumberConversion((Integer)map.get("beginPage"),pageCount);
    		int endPage=pageNumberConversion((Integer)map.get("endPage"),pageCount);
    		pagesData="AUTO_ADD:"+beginPage+","+endPage+","+horizontalOffset+","+0+","+255+","+matchingText+")|(4,";
    	}else if(sealRule.getType()==6){//多页绝对坐标
    		 int intervalType= (Integer)map.get("intervalType");
    		 int verticalDistance= (Integer)map.get("verticalDistance");
    		 int horizontalDistance= (Integer)map.get("horizontalDistance");
    		 int  firstPage=0;
    		 String strpage="";
    		 int thisPage=0;
    		 int intervalPage=2;
    		//奇数页firstPage=0intervalPage=2
    		//偶数页firstPage=1intervalPage=2
    		//指定页firstPage=01intervalPage=指定间隔
    		 if(intervalType==2){//偶数页
    			  firstPage=1;
    		 }else if(intervalType==3){//指定页
    			 intervalPage=(Integer)map.get("intervalPage");
    		 }
    		 while (thisPage<pageCount) {
				  thisPage=thisPage+intervalPage;
				  strpage+=","+thisPage;
			  }
    		 strpage=strpage.substring(1);
    		 pagesData=firstPage+","+horizontalDistance+",5,5,"+verticalDistance+","+strpage+",";
    		 log.info(pagesData);
    	}
    	return pagesData;
    }

	/**
	 * 页码转换 -1表示最后一页
	 * @param pageNumber 页码
	 * @param countPageNumber 总页数
	 * @return
	 */
    int pageNumberConversion(int pageNumber,int countPageNumber){
    	return pageNumber=pageNumber==-1?countPageNumber-1:pageNumber-1;
    }

	/**
	 * 模板合成及base64转文件
	 * @param TREE_NODES
	 * @param beginTime
	 * @param msgMap
	 */
	void  templateSynthesis(List<Element> TREE_NODES, String beginTime,Map msgMap){
    	log.info(beginTime+":模板合成开始");
    	init();
    	for(int i=0;i<TREE_NODES.size();i++){
	  		String fname=new Date().getTime()+"";
    		fname=	beginTime+"-"+fname;
    		String savePath=templateSynthesisPath+ "/"+fname+".pdf";
			//syntheticType = "ofd";
			//String savePath=templateSynthesisPath+ "/"+fname+".ofd";
    		Element TREE_NODE=TREE_NODES.get(i);
    		//得到fileNo文件类型是
			String  endFileNo = TREE_NODE.elementText("FILE_NO");
			int len = endFileNo.lastIndexOf(".");
			String fileSuffix = endFileNo.substring(len);
			syntheticType = "pdf";
			if(".ofd".equals(fileSuffix)){
				syntheticType = "ofd";
				savePath=templateSynthesisPath+ "/"+fname+".ofd";
			}
    		String CJ_TYPE=TREE_NODES.get(i).elementText("CJ_TYPE");
    		if(CJ_TYPE.equalsIgnoreCase("data")||CJ_TYPE.equalsIgnoreCase("base64")){
    			Element APP_DATA =TREE_NODE.element("APP_DATA");
    			int nObjID = openObj("", 0, 0);
    			log.info(beginTime+":nObjID:"+nObjID);

    			int msg=1;
    			Map map=new HashMap<String, String>();
            	if(nObjID<=0){
            		log.info(beginTime+":服务器繁忙，请稍后重试2");
            		map.put("FILE_MSG", "服务器繁忙，请稍后重试2");
            		map.put("RET_CODE", "0");
        			msgMap.put(i, map);
        			continue;
            	}
				int l = login(nObjID, 2,"HWSEALDEMOXX","");
				log.info(beginTime+":login:" + l);
				int x=0;
				try {
    				String MODEL_NAME= TREE_NODE.elementText("MODEL_NAME");
    				if("data".equalsIgnoreCase(CJ_TYPE)){
    					TemplateAIP templateAip=Cache.getTemplateAipByName(MODEL_NAME);
    					if(templateAip==null){
    						log.info(fname+":模板不存在，模板名："+MODEL_NAME);
    						map.put("RET_CODE", "0");
    						map.put("FILE_MSG", "模板不存在，模板名："+MODEL_NAME);
    						msg=0;
    						msgMap.put(i, map);
        			}
        		    int addPageRet=addPage(nObjID, "STRDATA:"+templateAip.getContentData(),xmlToAipData(APP_DATA),beginTime);
        			log.info(fname+":addPage:"+addPageRet);
        			if(addPageRet!=1){
        				log.info(fname+":添加文档"+i+"时失败");
        				map.put("RET_CODE", "0");
        				map.put("FILE_MSG", "添加文档"+i+"时失败");
        				msg=0;//return "添加文档"+i+"时失败";
        				msgMap.put(i, map);
        			}
    				}else if("base64".equalsIgnoreCase(CJ_TYPE)){
    					int addPageRet=addPage(nObjID, "STRDATA:"+MODEL_NAME,xmlToAipData(APP_DATA),beginTime);
    					log.info(fname+":addPage:"+addPageRet);
    					if(addPageRet!=1){
    						log.info(fname+":添加文档"+i+"时失败");
    						map.put("RET_CODE", "0");
    						map.put("FILE_MSG", "添加文档"+i+"时失败");
    						msg=0;
    						msgMap.put(i, map);
    					}
    				}
    				if(msg!=0){
						//int saveFileRet=saveFile(nObjID,savePath, "pdf", 1);
						int saveFileRet;
						if(".ofd".equals(fileSuffix)){
							saveFileRet=saveFile(nObjID,savePath, "ofd", 1);
						}else{
							saveFileRet=saveFile(nObjID,savePath, "pdf", 1);
						}

    					log.info(fname+":saveFile:"+saveFileRet);
    					if(saveFileRet==0){
    						log.info(fname+":saveFile文档保存失败，请检查服务器，保存路径："+savePath);
    						msg=0;
			      			map.put("RET_CODE", "0");
			      			map.put("FILE_MSG", "saveFile文档保存失败");
			      			msgMap.put(i, map);
    					}else{
    						log.info(fname+":saveFile文档保存成功"+new Date()+"保存路径："+savePath);
    						map.put("RET_CODE", "1");
    						map.put("FILE_MSG", savePath);
    						map.put("FILE_NO",fname);
    						msgMap.put(i, map);
    					}
    				}
    			} catch (Exception e) {
    				e.printStackTrace();
    			}finally {
       			  	log.info(fname+":templateSynthesis文档关闭");
       			  	saveFile(nObjID, "", syntheticType, 0);
       		 	}
    		}
    	}
  	 }

	public int documentToImg(byte[] fileData, final String requestNo){
		int pageCount;
		log.debug("[{}]:打开文档", requestNo);
		final int nObjID = openData(fileData);
		if (nObjID <= 0) {
			log.warn("[{}]:打开文档失败,nObjID:[{}]", requestNo, nObjID);
			return 0;
		}
		log.debug("[{}]:打开, nObjID:[{}]", requestNo, nObjID);
		try{
			log.debug("[{}]:登录, nObjID:[{}]", requestNo, nObjID);
			int l = login(nObjID, 2, "HWSEALDEMOXX", "");
			if(l != 0){
				log.warn("[{}]:登录失败,login:[{}]", requestNo, l);
				throw new Exception();
			}

			pageCount = srvSealUtil.getPageCount(nObjID);
			documentToImgThread.execute(
					new Runnable() {
						@Override
						public void run() {
							djPdfToImgUtil.getImgs(nObjID, requestNo);
						}
					}
			);
		} catch (Exception e){
            saveFile(nObjID, "", syntheticType, 0);
            log.debug("[{}]:失败关闭, nObjID:[{}]", requestNo, nObjID);
			return -1;
		}
		return pageCount;
	}

	private static byte[] chgBs(byte[] pdfbs, int pos, byte[] singedData) throws Exception {
		byte[] insertBs = new byte[singedData.length * 2];
		for (int i = 0; i < singedData.length; i++) {
			byte[] temp = bt2bt(singedData[i]);
			insertBs[i * 2] = temp[0];
			insertBs[i * 2 + 1] = temp[1];
		}
		int length = insertBs.length;
		for (int i = pos; i < pos + length; i++) {
			pdfbs[i] = insertBs[i - pos];
		}
		return pdfbs;
	}
	
	private static byte[] bt2bt(byte b) throws Exception {
		byte[] rb = new byte[2];
		int i1 = (0xf0 & b) >> 4;
		int i2 = 0x0f & b;
		rb[0] = toByte(i1);
		rb[1] = toByte(i2);
		return rb;
	}
	
	private static byte toByte(int i) throws Exception {
		byte b;
		switch (i) {
		case 0:
			b = '0';
			break;
		case 1:
			b = '1';
			break;
		case 2:
			b = '2';
			break;
		case 3:
			b = '3';
			break;
		case 4:
			b = '4';
			break;
		case 5:
			b = '5';
			break;
		case 6:
			b = '6';
			break;
		case 7:
			b = '7';
			break;
		case 8:
			b = '8';
			break;
		case 9:
			b = '9';
			break;
		case 10:
			b = 'a';
			break;
		case 11:
			b = 'b';
			break;
		case 12:
			b = 'c';
			break;
		case 13:
			b = 'd';
			break;
		case 14:
			b = 'e';
			break;
		default:
			b = 'f';
			break;
		}
		return b;
	}
	public void deleteFile(String url){
		File f=	new File(url);
		f.delete();
	}
	public static String getP7FromP1(String certPath, byte[] signedAttributes, byte[] oridata) throws Exception{
		System.out.println(certPath);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream inStream1 = new FileInputStream(certPath);
		X509Certificate x509=(X509Certificate) cf.generateCertificate(inStream1);
		inStream1.close();
		X509Certificate[] certificates=new X509Certificate[1];
		certificates[0]=x509;

		//下面这句可以构造出detach的p7
		//        ContentInfo contentInfo = new ContentInfo(ContentInfo.DATA_OID, null);
		//下面这句可以构造出attach的p7
		ContentInfo contentInfo = new ContentInfo(oridata);
		java.math.BigInteger serial = x509.getSerialNumber();
		System.out.println(x509.getIssuerDN().getName());
		SignerInfo si = new SignerInfo(new X500Name(x509.getIssuerDN().getName()), // X500Name, issuerName,
				serial, // x509.getSerialNumber(), BigInteger serial,
				AlgorithmId.get("SHA1"), // AlgorithmId,
				// digestAlgorithmId,
				null, // PKCS9Attributes, authenticatedAttributes,
				new AlgorithmId(AlgorithmId.RSAEncryption_oid), // AlgorithmId,
				// digestEncryptionAlgorithmId,
				signedAttributes, // byte[] encryptedDigest,
				null); // PKCS9Attributes unauthenticatedAttributes) {

		SignerInfo[] signerInfos = { si };

		// 构造PKCS7数据
		AlgorithmId[] digestAlgorithmIds = { AlgorithmId.get("SHA1") };
		PKCS7 p7 = new PKCS7(digestAlgorithmIds, contentInfo, certificates,
				signerInfos);
		ByteArrayOutputStream baout = new ByteArrayOutputStream();
		p7.encodeSignedData(baout);
		// Base64编码
		String base64Result=new String(Base64.encodeBase64String(baout.toByteArray()));
		if(base64Result!=null){
			System.out.println("getP7FromP1:"+base64Result.length());
		}
		return base64Result;
	}
	/**
	 * linux下有效
	 * alone 独立 合并时会先合成模板
	 * normal 正常直接合并
	 */
	enum  SyntheticMode{
		alone,normal
	}

    /**
     * 插入水印
     * @param element
     * @param beginTime
     * @return
     */
    String insertWatermark(Element element, String beginTime,String openPath,String savePath,String syntheticType) {
        String IS_WATERMARK = element.elementText("IS_WATERMARK");
        if ("true".equalsIgnoreCase(IS_WATERMARK)) {
            log.info(beginTime + ":插入水印开始");
            String WATERMARK_MODE = element.elementText("WATERMARK_MODE");//水印模式 short 设置或返回水印模式： 1：居中 (文字)2：平铺 (文字)3：居中带阴影(文字)4：平铺带阴影(文字)7：指定像素值
            String WATERMARK_ALPHA = element.elementText("WATERMARK_ALPHA");//水印透明度值范围：1到63，愈大愈透明。
/*
            String WATERMARK_TYPE = element.elementText("WATERMARK_TYPE");//水印类型1是文字水印2是图片水印
*/
            String WATERMARK_TEXTORPATH = element.elementText("WATERMARK_TEXTORPATH");//文字水印信息或图片base64数据
            String WATERMARK_POSX = element.elementText("WATERMARK_POSX");//水印在文档的x坐标位置
            String WATERMARK_POSY = element.elementText("WATERMARK_POSY");//水印在文档的y坐标位置
            String WATERMARK_TEXTCOLOR = element.elementText("WATERMARK_TEXTCOLOR");//水印文字颜色
            String WATERMARK_ANGLE = element.elementText("WATERMARK_ANGLE");//旋转角度
            String WATERMARK_TXTHORIMGZOOM = element.elementText("WATERMARK_TXTHORIMGZOOM");//缩放比例*/
/*
            log.info(":WATERMARK_TYPE:" + WATERMARK_TYPE);
*/
            String insertWatermarkret = insertWatermark(WATERMARK_MODE, WATERMARK_ALPHA, WATERMARK_TEXTORPATH, WATERMARK_POSX, WATERMARK_POSY, WATERMARK_TEXTCOLOR, WATERMARK_ANGLE, WATERMARK_TXTHORIMGZOOM,beginTime,openPath,savePath,syntheticType);
            if (!"ok".equals(insertWatermarkret)) {
                return insertWatermarkret;
            } else return "ok";

        } else return "ok";

    }

    /**
     * @param watermarkMode          水印模式 short 设置或返回水印模式： 1：居中 (文字)2：平铺 (文字)3：居中带阴影(文字)4：平铺带阴影(文字)7：指定像素值
     * @param watermarkAlpha         水印透明度值范围：1到63，愈大愈透明。
     * @param watermarkTextorpath    文字水印信息或图片base64数据
     * @param watermarkPosx          水印在文档的x坐标位置
     * @param watermarkPosy          水印在文档的y坐标位置
     * @param watermarkTextcolor     水印文字颜色
     * @param watermarkAngle         旋转角度
     * @param watermarkTxthorimgzoom 缩放比例
     * @param beginTime
     * @return
     */
    private String insertWatermark(String watermarkMode, String watermarkAlpha, String watermarkTextorpath, String watermarkPosx, String watermarkPosy, String watermarkTextcolor, String watermarkAngle, String watermarkTxthorimgzoom, String beginTime,String openPath,String savePath,String syntheticType) {
        int nObjID=0;
        /*添加水印信息*/
        if(System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1){
            //window环境
            nObjID = srvSealUtil.openObj(openPath, 0, 0);
            log.info("windows下水印nObjID:" + nObjID);
            if (nObjID <= 0) {
                log.info(":服务器繁忙，请稍后重试3");
                return null;
            }
            int login = srvSealUtil.login(nObjID, 2, "HWSEALDEMOXX", "");
            if(login!=0){
                int s1=srvSealUtil.saveFile(nObjID, "",syntheticType,0);
                if(s1==1){
                    log.info("关闭文档成功");
                }else{
                    log.info("关闭文档失败");
                }
                return null;
            }
        }else{
            nObjID=srvSealUtil.openObj(openPath,1);
            log.info("linux下水印nObjID:"+nObjID);
            if(nObjID<=0){
                log.info("x-openObj打开文档失败返回值是："+nObjID);
                return null;
            }
/*
            int login = srvSealUtil.login(nObjID, "seal", 2, "");//解决了aip打开pdf后用户信息是测试用户
*/
            int login=login(nObjID,2,"","");
            log.info("水印login:" + login);
            if(login!=0){
                int s1=srvSealUtil.saveFile(nObjID, "");
                if(s1==1){
                    log.info("关闭文档成功");
                }else{
                    log.info("关闭文档失败");
                }
                log.info("x-登录失败，返回值是："+login);
                return null;
            }
        }
        try {
            log.info("WATERMARK_MODE水印模式:"+watermarkMode);
            if ("1".equals(watermarkMode)||"2".equals(watermarkMode)) {//文字水印
                log.info("WATERMARK_MODE:"+srvSealUtil.setValue(nObjID, "SET_WATERMARK_MODE", watermarkMode));
                log.info("TEXTORPATH:"+srvSealUtil.setValue(nObjID, "SET_WATERMARK_TEXTORPATH", watermarkTextorpath));
                log.info("TEXTCOLOR:"+srvSealUtil.setValue(nObjID, "SET_WATERMARK_TEXTCOLOR", watermarkTextcolor));
            } else if ("5".equals(watermarkMode)||"6".equals(watermarkMode)) {//图片水印
                log.info("WATERMARK_MODE:"+srvSealUtil.setValue(nObjID, "SET_WATERMARK_MODE", watermarkMode));
                if(System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1){
                    log.info("TEXTORPATH:"+srvSealUtil.setValue(nObjID, "SET_WATERMARK_TEXTORPATH","STRDATA:"+watermarkTextorpath));
                }else{
                    //linux仅支持本地路径图片传入
                    String  picture=Util.getSystemDictionary("upload_path")+new Date().getTime()+".bmp";
                    log.info("picture,图片转换路径"+picture);
                    if(Util.GenerateImage(watermarkTextorpath,picture)){
                        log.info("TEXTORPATH:"+srvSealUtil.setValue(nObjID, "SET_WATERMARK_TEXTORPATH",picture));
/*                        File file=new File(picture);
                        file.delete();*/
                    }else{
                        return null;
                    }
                }
            }else{
                log.info(":不正确的水印添加模式");
                return null;
            }
            log.info("ALPHA:"+ srvSealUtil.setValue(nObjID, "SET_WATERMARK_ALPHA", watermarkAlpha));
            log.info("POSX:"+ srvSealUtil.setValue(nObjID, "SET_WATERMARK_POSX", watermarkPosx));
            log.info("POSY:"+ srvSealUtil.setValue(nObjID, "SET_WATERMARK_POSY", watermarkPosy));
            log.info("ANGLE:"+  srvSealUtil.setValue(nObjID, "SET_WATERMARK_ANGLE", watermarkAngle));
            log.info("TXTHORIMGZOOM:"+ srvSealUtil.setValue(nObjID, "SET_WATERMARK_TXTHORIMGZOOM", watermarkTxthorimgzoom));
            if(System.getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1){//window环境
                int s=srvSealUtil.saveFile(nObjID,savePath,syntheticType,0);
                if(s==1){
                    log.info(":加盖水印成功");
                    return "ok";
                }
            }else{
/*
                int s=srvSealUtil.saveFile(nObjID,savePath);
*/
                int s=srvSealUtil.saveFileEx(nObjID,savePath,0);

                if(s==1){
                    log.info(":加盖水印成功");
                    return "ok";
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        log.info(beginTime + ":加盖水印失败");
        return null;
    }

    private SrvSealUtil srvSealUtil;
	private int qifenCount;
	private String path=null;
	private String syntheticType= null;
	private String sealFilePath=null;
	private String templateSynthesisPath=null;
	@Autowired
	private DepartmentDao departmentDao;
	@Autowired
	private SealDao sealDao;
}
