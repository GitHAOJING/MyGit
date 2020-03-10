package com.dianju.modules.org.controllers;


import com.dianju.core.AuthorizationException;
import com.dianju.core.EncryptionAndDecryption.DES.DesUtil;
import com.dianju.core.EncryptionAndDecryption.MD5.MD5Util;
import com.dianju.core.EncryptionAndDecryption.RSA.RSAUtil;
import com.dianju.core.EncryptionAndDecryption.SHA.SHAUtil;
import com.dianju.core.ErrorCode;
import com.dianju.core.LicenseConfig;
import com.dianju.core.Response;
import com.dianju.core.SystemListener;
import com.dianju.core.Util;
import com.dianju.core.models.DaoUtilImpl;
import com.dianju.core.models.pageAndSizeException;
import com.dianju.modules.log.models.LogSealUseDao;
import com.dianju.modules.log.models.LogSystemDao;
import com.dianju.modules.org.models.*;
import com.dianju.modules.org.models.user.ManageDepartment;
import com.dianju.modules.org.models.user.User;
import com.dianju.modules.org.models.user.UserCertDao;
import com.dianju.modules.org.models.user.UserDao;
import com.dianju.modules.public_.controllers.AuthorizationController;
import com.dianju.modules.seal.controllers.SealController;
import com.dianju.modules.seal.models.Seal;
import com.dianju.modules.seal.models.SealDao;
import com.dianju.modules.seal.models.UserSeal;
import com.dianju.signatureServer.check.OACheck;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.dvcs.CertEtcToken;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.jpa.JpaObjectRetrievalFailureException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 用户Controller
 * @author liuchao
 * @date 2016-6-28
 */
@RestController
@RequestMapping("/api")
@SuppressWarnings({"rawtypes", "unchecked"})
public class UserController {
	

	private int UPDATAPASSWORDTIMEOUT;
	/**
	 * 添加用户
	 * @param users
	 * @return
	 */
	@RequestMapping(path = "/user", method = RequestMethod.POST, consumes = "application/json")
    public ResponseEntity create(@RequestBody List<User> users, HttpSession session) {
    	try {
    		ServletContext servletContext=session.getServletContext();
    		Map<String,String> KEY=(Map)servletContext.getAttribute("KEY");
    	
			for(int i=0;i<users.size();i++){
				User user = users.get(i);
				//验证用户名是否已存在
				if(userDao.findUserByLoginId(user.getLoginId()) == null) {
                    //验证绑定证书是否已存在
                    if (user.getCertSn() != null ) {
                        if(userDao.getUserBy_certSn(user.getCertSn()) != null){
                            return new ResponseEntity<>(new Response(ErrorCode.ERR_CERTNAME_EXISTS,"绑定证书已存在"),HttpStatus.INTERNAL_SERVER_ERROR);
                        }
                    }
                    user.setPasswordUpdatedAt(Util.getTimeStampOfNow());
                    //将密码解密
                    String password;
                    try {
                        password = SHAUtil.getSha256(Util.getPasswordBase64Decode(user.getPassword()));//将密码再一次加密
                    } catch (Exception e) {
                        e.printStackTrace();
                        return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_ERROR, "密码解析失败"), HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                    user.setPassword(password);
                    //设置用户创建人
                    User u = (User) session.getAttribute("loginUser");
                    user.setLastReadMessageTime(Util.getTimeStampOfNow());
                    if (u == null) {//报文添加
                        user.setCreatedBy("u1");
                    } else {
                        user.setCreatedBy(u.getId());
                    }

				}else{
					return new ResponseEntity<>(new Response(ErrorCode.ERR_USER_UN_EXISTS, "用户名已存在"), HttpStatus.INTERNAL_SERVER_ERROR);
				}
			}
			
			
			userDao.save(users);
			return new ResponseEntity<>(null, HttpStatus.OK);
		} catch(DataIntegrityViolationException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		} catch(JpaObjectRetrievalFailureException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		} catch(AuthorizationException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
		} catch (Exception e) {
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		}
    }

	/**
	 * OA添加用户
	 * @param xmlStr 请求报文
	 * @param request
	 * @return
	 */
	public String addUser(String xmlStr,Long beginTime, HttpServletRequest request) {
	    try{
            HttpSession session = request.getSession();
            Document doc = DocumentHelper.parseText(xmlStr);
            Element addUserRequest = doc.getRootElement();
            Element metaData = addUserRequest.element("META_DATA");
            String returnXml = null;
            List<User> users = new ArrayList<>();
			OACheck check = new OACheck(beginTime+"");
			if (!check.OAUserAdd(addUserRequest,request)){
				//xml格式判断失败
				returnXml = getReturnXml(null,"",beginTime,check.getError());
			}else{
				//xml格式判断成功
				String IS_BINDCERT = metaData.elementText("IS_BINDCERT");
				String IS_ACCREDIT = metaData.elementText("IS_ACCREDIT");
				String SEAL_NAME = "";
				Seal seal = new Seal();
				Element USER_LIST = addUserRequest.element("USER_LIST");
				List<Element> TREE_NODES = USER_LIST.elements("TREE_NODE");
				for (int i = 0; i <TREE_NODES.size() ; i++) {
					User user = new User();
					Element t = TREE_NODES.get(i);
					String CERTIFICATE_TYPE = t.elementText("CERTIFICATE_TYPE");
					//必填项
					user.setLoginId(t.elementText("LOGIN_ID"));
					user.setName(t.elementText("NAME"));
					//密码加密
					String pwd = t.elementText("PASSWORD");
					//16进制Sha256值
					String base64Str = getSHA256HEX(pwd);
					//DES加密
					String key = new AuthorizationController().getProofCode(session).toString().split(",")[1];
					//用base64编码方式加密
					final Base64 base64 = new Base64();
					String password = base64.encodeToString(encryptDES(base64Str.getBytes(),key.getBytes()));
					user.setPassword(password);
					//Department department = departmentDao.findOne(t.elementText("DEPARTMENT_ID"));
					Department department = new Department();
					if (("").equals(t.elementText("DEPARTMENT_ID"))){//默认根部门
						department = departmentDao.findOne("0000000000000000000001");
					}else{//用otherID查询部门
						department = departmentDao.findDepByOtherId(t.elementText("DEPARTMENT_ID"));
					}
					user.setDepartment(department);

					String RBAC_ROLES[] = t.elementText("RBAC_ROLES").split(",");
					Set<RbacRole> roles = new HashSet<>();
					for (int j = 0; j <RBAC_ROLES.length ; j++) {
						roles.add(rbacRoleDao.findOne(RBAC_ROLES[j]));
					}
					user.setRbacRoles(roles);

					//状态默认1
					if (("").equals(getElementVal(t,"STATUS"))){
						user.setStatus(Byte.valueOf("1"));
					}else{
						user.setStatus(Byte.valueOf(t.elementText("STATUS")));
					}
					//选填项
					//性别默认1
					if (("").equals(getElementVal(t,"GENDER"))){
						user.setGender(Byte.valueOf("1"));
					}else{
						user.setGender(Byte.valueOf(t.elementText("GENDER")));
					}

					user.setEmail(getElementVal(t,"EMAIL"));
					user.setBirthday(("").equals(getElementVal(t,"BIRTHDAY"))?0:Integer.valueOf(getElementVal(t,"BIRTHDAY")));
					user.setWorkTelephone(getElementVal(t,"WORK_TELEPHONE"));
					user.setMobile(getElementVal(t,"MOBILE"));
					user.setUserType(("").equals(getElementVal(t,"USER_TYPE"))?0L:Long.valueOf(getElementVal(t,"USER_TYPE")));
					user.setCurrentRole(("").equals(getElementVal(t,"CURRENT_ROLE"))?"0":getElementVal(t,"CURRENT_ROLE"));
					//TODO 管理部门
					if ("true".equals(IS_BINDCERT)){//绑定证书
						//证书基本信息
						user.setCertSn(t.elementText("CERT_SN"));
						user.setCertDn(t.elementText("CERT_DN"));
						user.setCertValidityBegin(Long.parseLong(t.elementText("CERTVALIDITY_BEGIN")));
						user.setCertValidityEnd(Long.parseLong(t.elementText("CERTVALIDITY_END")));
						user.setCertPublicKey(t.elementText("CERT_PUBLIC"));
						user.setCertificateType(Byte.valueOf(CERTIFICATE_TYPE));
						if("2".equals(CERTIFICATE_TYPE)){//绑定pfx证书
							user.setCertContent(t.elementText("CERT_CONTENT"));
							user.setCertPassword(t.elementText("CERT_PASSWORD"));
						}
					}
					users.add(user);
					/*//如果授权
					if("true".equals(IS_ACCREDIT)){
						SEAL_NAME = t.elementText("SEAL_NAME");

					//印章是否存在
					seal = sealDao.findByName1(SEAL_NAME);
						if(null == seal){//不存在印章
							return getReturnXml(null,IS_BINDCERT,beginTime,"授权印章不存在");
						}
						//印章类型 单授权/多授权
						if(seal.getType() == 7||seal.getType() == 8||seal.getType()==9){//单授权
							List<UserSeal> userSealList = sealDao.findBySealId(seal.getId());
							if (0 == userSealList.size()){//未被授权
								String sealRet = setUserSeal(seal.getId(),user.getId(),beginTime);
								if(("no").equals(sealRet)){//授权不成功
									return getReturnXml(null,"",beginTime,"印章授权失败");
								}
							}else{
								return getReturnXml(null,IS_BINDCERT,beginTime,"该印章已被授权");
							}
						}else{//可多个用户授权
							setUserSeal(seal.getId(),user.getId(),beginTime);
						}
					}*/
				}
				//先添加用户 再授权
				ResponseEntity re = create(users,session);
				if (re.getStatusCodeValue() != 200){//添加用户失败
					/*//选择印章授权 授权成功 添加用户未成功 删除授权数据
					for (int i = 0; i < users.size(); i++) {
						if(null == userDao.findOne(users.get(i).getId())){//用户未添加
							if(null != sealDao.getSealsByUser(users.get(i).getId())){//用户印章表记录不为空
								sealDao.deleteByUserId(users.get(i).getId());
							}
						}
					}*/
					return getReturnXml(null,IS_BINDCERT,beginTime,"用户名/用户证书已存在");
				}else{//添加用户成功 授权
					for (int i = 0; i <users.size() ; i++) {
						User user = users.get(i);
						for (int j = 0; j <TREE_NODES.size() ; j++) {
							Element t = TREE_NODES.get(j);
							//如果授权
							if("true".equals(IS_ACCREDIT)){
								SEAL_NAME = t.elementText("SEAL_NAME");
								//印章是否存在
								seal = sealDao.findByName1(SEAL_NAME);
								if(null == seal){//不存在印章
									return getReturnXml(users,IS_BINDCERT,beginTime,user.getId()+"授权印章不存在");
								}
								//印章类型 单授权/多授权
								if(seal.getType() == 7||seal.getType() == 8||seal.getType()==9){//单授权
									List<UserSeal> userSealList = sealDao.findBySealId(seal.getId());
									if (0 == userSealList.size()){//未被授权
										String sealRet = setUserSeal(seal.getId(),user.getId(),beginTime);
										if(("no").equals(sealRet)){//授权不成功
											return getReturnXml(users,"",beginTime,user.getLoginId()+"印章授权失败");
										}
									}else{
										return getReturnXml(users,IS_BINDCERT,beginTime,user.getLoginId()+"授权印章已被授权");
									}
								}else{//可多个用户授权
									String sealRet = setUserSeal(seal.getId(),user.getId(),beginTime);
									if(("no").equals(sealRet)){//授权不成功
										return getReturnXml(users,"",beginTime,user.getLoginId()+"印章授权失败");
									}
								}
							}
						}
					}

				}
				returnXml = getReturnXml(users,IS_BINDCERT,beginTime);
			}

            return returnXml;
        }catch (DocumentException e){
	    	e.printStackTrace();
	    	return getReturnXml(null,"",beginTime,"xml解析失败");
        }catch (Exception e){
	    	e.printStackTrace();
	    	return getReturnXml(null,"",beginTime,"添加用户失败");
		}
	}

	/**
	 * OA服务端修改用户绑定cert证书
	 * @param xmlStr
	 * @param beginTime
	 * @param request
	 * @return
	 */
	public String updateOAUserCert(String xmlStr,Long beginTime, HttpServletRequest request){
		try{
			HttpSession session = request.getSession();
			Document doc = DocumentHelper.parseText(xmlStr);
			Element updateUserCertRequest = doc.getRootElement();
			String returnXml = null;
			List<User> users = new ArrayList<>();
			OACheck check = new OACheck(beginTime+"");
			if (!check.OAUserCertUpdate(updateUserCertRequest,request)){
				//xml格式判断失败
				returnXml = getReturnXml(null,null,beginTime,check.getError());
			}else{
				//xml格式判断成功
				Element USER_LIST = updateUserCertRequest.element("USER_LIST");
				List<Element> TREE_NODES = USER_LIST.elements("TREE_NODE");
				for (int i = 0; i <TREE_NODES.size() ; i++) {
					Element ele = TREE_NODES.get(i);
					//多条件查询 三者不可同时为空
					String LOGIN_ID = ele.elementText("LOGIN_ID");
					String OLD_CERTSN = ele.elementText("OLD_CERTSN");
					String OLD_CERTDN = ele.elementText("OLD_CERTDN");
					User user = new User();
					User befUser = new User();
					if (null != LOGIN_ID && !(("").equals(LOGIN_ID))){//根据用户名查询
						befUser =  userDao.findUserByLoginId(LOGIN_ID);
						if(befUser==null){//用户不存在
							return getReturnXml(null,null,beginTime,"用户不存在");
						}
						user = setVal(user,befUser);
					}else if(null != OLD_CERTSN && !(("").equals(OLD_CERTSN))){//根据certsn查询
						befUser = userDao.getUserBy_certSn(OLD_CERTSN);
						if(befUser==null){//用户不存在
							return getReturnXml(null,null,beginTime,"用户不存在");
						}
						user = setVal(user,befUser);
					}else if(null != OLD_CERTDN && !(("").equals(OLD_CERTDN))){//根据certdn查询
						befUser = userDao.getUserBy_certDn(OLD_CERTDN);
						if(befUser==null){//用户不存在
							return getReturnXml(null,null,beginTime,"用户不存在");
						}
						user = setVal(user,befUser);
					}else{
						return getReturnXml(null,null,beginTime,"用户信息为空");
					}

					//新Cert证书信息
					String CERT_SN = ele.elementText("CERT_SN");
					if(userDao.getUserBy_certSn(CERT_SN) != null){//证书已被其他用户绑定
						return getReturnXml(null,null,beginTime,"该证书已被绑定");
					}
					String CERT_DN = ele.elementText("CERT_DN");
					String CERT_PUBLIC = ele.elementText("CERT_PUBLIC");
					String CERTVALIDITY_BEGIN = ele.elementText("CERTVALIDITY_BEGIN");
					String CERTVALIDITY_END = ele.elementText("CERTVALIDITY_END");
					user.setCertificateType(Byte.valueOf("4"));//cert证书
					user.setUserType(0);//userType
					user.setCertSn(CERT_SN);
					user.setCertDn(CERT_DN);
					user.setCertPublicKey(CERT_PUBLIC);
					user.setCertValidityBegin(Integer.valueOf(CERTVALIDITY_BEGIN));
					user.setCertValidityEnd(Integer.valueOf(CERTVALIDITY_END));

					users.add(user);
				}

				userDao.save(users);
				returnXml = getReturnXml(users,null,beginTime);
			}
			return returnXml;
		}catch (DocumentException e){
			e.printStackTrace();
			return getReturnXml(null,null,beginTime,"xml解析失败");
		}catch (Exception e){
			e.printStackTrace();
			return getReturnXml(null,null,beginTime,"修改pfx证书失败");
		}
	}
	User setVal(User nullUser,User oldUser){
		nullUser.setId(oldUser.getId());
		nullUser.setLoginId(oldUser.getLoginId());
		nullUser.setName(oldUser.getName());
		nullUser.setGender(oldUser.getGender());
		nullUser.setStatus(oldUser.getStatus());
		nullUser.setPassword(oldUser.getPassword());
		nullUser.setEmail(oldUser.getEmail());
		nullUser.setMobile(oldUser.getMobile());
		nullUser.setWorkTelephone(oldUser.getWorkTelephone());
		nullUser.setBirthday(oldUser.getBirthday());
		nullUser.setDepartment(oldUser.getDepartment());
		nullUser.setRbacRoles(oldUser.getRbacRoles());
		nullUser.setCreatedAt(oldUser.getCreatedAt());
		nullUser.setCreatedBy(oldUser.getCreatedBy());
		nullUser.setCurrentRole(oldUser.getCurrentRole());
		nullUser.setPasswordUpdatedAt(oldUser.getPasswordUpdatedAt());
		nullUser.setLastReadMessageTime(oldUser.getLastReadMessageTime());
		nullUser.setOtherId(oldUser.getOtherId());
		nullUser.setClientType(oldUser.getClientType());
		nullUser.setUpdatedAt();
		return nullUser;
	}
	String setUserSeal(String sealId,String userId,long beginTime){
		Map userSeals = new HashMap();
		ArrayList  userIdsList = new ArrayList();
		userIdsList.add(userId);
		userSeals.put("sealId",sealId);
		userSeals.put("userIds",userIdsList);
		ResponseEntity re = sealController.getUserSeals(userSeals);
		if (re.getStatusCodeValue() != 200){//错误返回值
			return "no";
		}
		return "ok";
	}
	String getElementVal(Element t,String eleName){
		if (t.element(eleName)==null || t.elementText(eleName)==null){
			return "";
		}else{
			return t.elementText(eleName);
		}
    }
    private String getReturnXml(List<User> users,String IS_BINDCERT,Long beginTime,String... checkMsg){
		//String retXml = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"+"<ADD_USER_RESPONSE>";
		//(syntheticPattern==SyntheticPattern.AddSeal?"<SEAL_DOC_RESPONSE>":"<MODEL_REQUEST>")
		String retXml = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"+(IS_BINDCERT != null?"<ADD_USER_RESPONSE>":"<UPDATE_USERCERT_RESPONSE>");
		String msg = "";
		//xml是否验证成功
		if (checkMsg.length == 0){
			msg = "<RET_CODE>" + 1 + "</RET_CODE>"
					+ "<RET_MSG>xml验证成功</RET_MSG>";

			Iterator iterator = users.iterator();
			msg += "<USER_LIST>";
			while (iterator.hasNext()) {
				User user = (User)iterator.next();//每个对象
				msg += "<USER><LOGIN_ID>" + user.getLoginId() + "</LOGIN_ID>"
						+ "<NAME>" + user.getName() + "</NAME>"
						+ "<DEPARTMENT>" +user.getDepartment().getName()+ "</DEPARTMENT>";
				//绑定证书
				if (user.getCertSn()!=null){
					msg += "<CERT_SN>" + user.getCertSn() + "</CERT_SN>"
							+"<CERT_DN>" + user.getCertDn() + "</CERT_DN>";
				}
				//授权印章
				List<Map<String,String>> sealList = sealDao.getSealsByUser(user.getId());
				if (null != sealList) {
					for (int i = 0; i < sealList.size(); i++) {
						//Iterator iterator1 = sealList.get(i).values().iterator();
						msg += "<SEAL_NAME>"+sealList.get(i).get("sname")+"</SEAL_NAME>";
						//Iterator iterator1 = (Map)(sealList.get(i)).get("sname").iterator();
						/*while (iterator1.hasNext()) {
							String sealName = (String)iterator1.next();
							msg += "<SEAL_NAME>"+sealName+"</SEAL_NAME>";
						}*/
					}
				}
				msg += "</USER>";
			}
			msg += "</USER_LIST>";
		}else{
			msg += "<RET_CODE>" + 0 + "</RET_CODE>"
					+ "<RET_MSG>" + checkMsg[0] + "</RET_MSG>";
					//+ "<USER_LIST></USER_LIST>";
			//添加用户成功 授权未成功
			if (null != users){
				Iterator iterator = users.iterator();
				msg += "<USER_LIST>";
				while (iterator.hasNext()) {
					User user = (User) iterator.next();//每个对象
					msg += "<USER><LOGIN_ID>" + user.getLoginId() + "</LOGIN_ID>"
							+ "<NAME>" + user.getName() + "</NAME>"
							+ "<DEPARTMENT>" + user.getDepartment().getName() + "</DEPARTMENT>";
					//绑定证书
					if (user.getCertSn() != null) {
						msg += "<CERT_SN>" + user.getCertSn() + "</CERT_SN>"
								+ "<CERT_DN>" + user.getCertDn() + "</CERT_DN>";
					}
					msg += "</USER>";
				}
				msg += "</USER_LIST>";
			}
		}
		retXml += "<ADD_TIME>" + (new Date().getTime() - beginTime) + "</ADD_TIME>"
				+ msg
				+ (IS_BINDCERT != null?"<ADD_USER_RESPONSE>":"<UPDATE_USERCERT_RESPONSE>");
		return retXml;
	}
	/*private String getReturnXmlPfx(List<User> users,Long beginTime,String... checkMsg){
		String retXml = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"+"<UPDATE_USERPFX_RESPONSE>";
		String msg = "";
		//xml是否验证成功
		if (checkMsg.length == 0){
			msg = "<RET_CODE>" + 1 + "</RET_CODE>"
					+ "<RET_MSG>xml验证成功</RET_MSG>";

			Iterator iterator = users.iterator();
			msg += "<USER_LIST>";
			while(iterator.hasNext()){
				User user = (User)iterator.next();//每个对象
				msg +=""
			}
			*//*while (iterator.hasNext()) {
				User user = (User)iterator.next();//每个对象
				msg += "<USER><LOGIN_ID>" + user.getLoginId() + "</LOGIN_ID>"
						+ "<NAME>" + user.getName() + "</NAME>"
						+ "<DEPARTMENT>" +user.getDepartment().getName()+ "</DEPARTMENT>";
				if (user.getCertSn()!=null){//绑定证书
					msg += "<CERT_SN>" + user.getCertSn() + "</CERT_SN>"
							+"<CERT_DN>" + user.getCertDn() + "</CERT_DN>";
					*//**//*if (user.getCertContent()!=null){//绑定pfx证书
						msg += "<CERT_CONTENT>" + user.getCertContent()+ "</CERT_CONTENT>";
					}*//**//*
				}
				msg += "</USER>";
			}*//*
			msg += "</USER_LIST>";
		}else{
			msg += "<RET_CODE>" + 0 + "</RET_CODE>"
					+ "<RET_MSG>" + checkMsg[0] + "</RET_MSG>"
					+ "<USER_LIST></USER_LIST>";
		}
		retXml += "<ADD_TIME>" + (new Date().getTime() - beginTime) + "</ADD_TIME>"
				+ msg
				+ "</UPDATE_USERPFX_RESPONSE>";
		return retXml;
	}*/
	/**
	 * 利用java原生的类实现SHA256加密
	 * @param str 加密后的报文
	 * @return
	 */
	public String getSHA256HEX(String str){
		//获取sha256值
		MessageDigest messageDigest;
		String encodestr = "";
		try{
		messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(str.getBytes("UTF-8"));
		encodestr = DesUtil.byteArr2HexStr(messageDigest.digest());
		}catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		}catch(UnsupportedEncodingException e){
			e.printStackTrace();
		}catch (Exception e){
			e.printStackTrace();
		}
		return encodestr;
	}
	public static byte[] encryptDES(byte[] encryptbyte, byte[] encryptKey) throws Exception {
		SecretKeySpec key = new SecretKeySpec(DesUtil.getKey(encryptKey).getEncoded(), "DES");
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		//decryptCipher.init(Cipher.DECRYPT_MODE, key,zeroIv);
		byte[] encryptedData = cipher.doFinal(encryptbyte);
		return encryptedData;
	}

    /**
     * 修改用户 -- 不可修改密码
     * @param users
     * @return
     */
	@RequestMapping(path = "/user", method = RequestMethod.PUT, consumes = "application/json")
    public ResponseEntity update(@RequestBody List<User> users) {
        try {
			//int time=(int) (System.currentTimeMillis()/1000);
			//for(int i=0;i<users.size();i++) {
			/*	User user = users.get(i);
				User thisUser=userDao.findOne(user.getId());
				//密码不可修改
				if(thisUser != null && thisUser.getId().equals( user.getId())) {
					//user.setUpdatedAt(time);
					user.setPasswordUpdatedAt(thisUser.getPasswordUpdatedAt());
					user.setPassword(thisUser.getPassword());
					user.setUserType(user.getUserType()|(thisUser.getUserType()&0xff00));
				}else {
					return new ResponseEntity<>(new Response(ErrorCode.ERR_USER_NOT_EXISTS, "用户不存在"), HttpStatus.INTERNAL_SERVER_ERROR);
				}*/
			//}
			userDao.save(users);
			return new ResponseEntity<>(true, HttpStatus.OK);
		}catch(DataIntegrityViolationException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		} catch(JpaObjectRetrievalFailureException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		}catch(AuthorizationException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
		} catch(Exception e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		}
     }
	
	/**
     * 维护个人信息 --只允许修改个人的基本信息
     * @param user
     * @return
     */
	@RequestMapping(path = "/userInfo", method = RequestMethod.PUT, consumes = "application/json")
    public ResponseEntity updateUser(@RequestBody User user, HttpSession session) {
        try {
			//int time=(int) (System.currentTimeMillis()/1000);
			
			//查询用户
			User thisUser=userDao.findOne(user.getId());
			
			//设置用户个人信息
			thisUser.setName(user.getName());
			thisUser.setBirthday(user.getBirthday());
			thisUser.setEmail(user.getEmail());
			thisUser.setGender(user.getGender());
			thisUser.setMobile(user.getMobile());
			//thisUser.setUpdatedAt(time);
			thisUser.setWorkTelephone(user.getWorkTelephone());
			
			//保存用户
			userDao.save(thisUser);
			
			//获取session里的用户
			User sessionUser = (User)session.getAttribute("loginUser");
	
			//修改信息
			sessionUser.setName(user.getName());
			sessionUser.setBirthday(user.getBirthday());
			sessionUser.setEmail(user.getEmail());
			sessionUser.setGender(user.getGender());
			sessionUser.setMobile(user.getMobile());
		//	sessionUser.setUpdatedAt(time);
			sessionUser.setWorkTelephone(user.getWorkTelephone());
			
			return new ResponseEntity<>(true, HttpStatus.OK);
        } catch(JpaObjectRetrievalFailureException e){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_DATA_INVALID, "userDepartments,userRoles,manageDepartments-departmentId不在有效的范围内或loginId重复"), HttpStatus.INTERNAL_SERVER_ERROR);
		}
     }
    
    /**
     * 删除用户
     * @param ids
     * @retur		
     */
	@RequestMapping(path = "/user", method = RequestMethod.DELETE, consumes = "application/json")
	@Transactional(rollbackFor=Exception.class)
    public ResponseEntity delete (@RequestBody String[] ids){
    	try {
    		for(int i=0;i<ids.length;i++){
    			userDao.delete(ids[i]);
				userCertDao.deleteByUserId(ids[i]);
		    }
    		return new ResponseEntity<>(true, HttpStatus.OK);	
	    }catch (Exception e) {   
	    	return new ResponseEntity<>(new Response(ErrorCode.ERR_USER_OCCUPY, "用户被占用"), HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

    /**
     * 用户高级搜索
     * @param userSearch
     * @return
     * @throws pageAndSizeException 
     */
	@RequestMapping(path = "/users", method = RequestMethod.GET,produces= "application/json")
    public ResponseEntity conditionQuery(@RequestParam Map userSearch,HttpSession session) throws pageAndSizeException {
		if(!(userSearch.containsKey("departmentId")&&userSearch.get("departmentId")!=null)){//第一次没有传部门
			Map userInfo=(Map)session.getAttribute("userInfo");
			Department department=(Department)userInfo.get("department");
			userSearch.put("departmentId", department.getId());
			if(	"false".equals(userInfo.get("LowerLevel")+"")){
				userSearch.put("lowerLevel", "false");
			}else { 
				userSearch.put("lowerLevel", Util.getSystemDictionary("defaultLowerLevel"));
			}
		}
		Page page=userDao.conditionQuery(userSearch);
    	return new ResponseEntity<>(page, HttpStatus.OK);
    }
    
    /**
	 * 用户查询（单个）
	 * @param id 用户id
	 * @return
	 */
	@RequestMapping(path = "/user/{id}", method = RequestMethod.GET)
	public ResponseEntity find(@PathVariable(value = "id") String id){
		User user = userDao.findOne(id);
		DaoUtilImpl.idToName(user);
		return new ResponseEntity<>(user,HttpStatus.OK);
	}
	
	/**
	 * 查询用户印章
	 * @param id
	 * @return
	 */
	@RequestMapping(path = "/userSeal/{id}", method = RequestMethod.GET)
	public ResponseEntity  getUserSeal(@PathVariable(value = "id") String id){
		return  new ResponseEntity<>(userDao.findUserAndSeal(id),HttpStatus.OK);
	} 
	
	/**
	 * 修改密码
	 * @param userInfo
	 * @return
	 */
	@RequestMapping(path = "/updatePw", method = RequestMethod.POST, consumes = "application/json")
	public ResponseEntity updatePassword(@RequestBody Map<String,String> userInfo){
		User user = userDao.findOne(userInfo.get("id"));
        //将密码解密
        String oldPassword;
        String newPassword;
        try{
            oldPassword = SHAUtil.getSha256(Util.getPasswordBase64Decode(userInfo.get("oldPassword")));//将密码再一次加密
            newPassword = SHAUtil.getSha256(Util.getPasswordBase64Decode(userInfo.get("newPassword")));
        }catch(Exception e){
            e.printStackTrace();
            return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_ERROR, "密码解析失败"), HttpStatus.INTERNAL_SERVER_ERROR);
        }
		if(user!=null&&oldPassword.equals(user.getPassword())) {
			int time=(int) (System.currentTimeMillis()/1000);

			//user.setUpdatedAt(time);
			user.setPasswordUpdatedAt(time);
			user.setPassword(newPassword);
			userDao.save(user);
			
			return new ResponseEntity<>(true, HttpStatus.OK);
		}else{
			return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_INVALID, "原密码不正确"), HttpStatus.FORBIDDEN);
		}
	} 
	
	/**
	  * 验证用户名唯一
	  * @param value
	  * @return 
	  */
	@RequestMapping(path = "/user/exist", method = RequestMethod.GET)
	public ResponseEntity exist(@RequestParam String value){
		if(userDao.findUserByLoginId(value) == null){
		    return new ResponseEntity<>(true,HttpStatus.OK);
		}else{
			return new ResponseEntity<>(new Response(ErrorCode.ERR_USER_UN_EXISTS, "用户名已存在"), HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
	
    /**
     * 用户登录
     * @param loginInfor
     * @param session
     * @return
     * @throws pageAndSizeException 
     */
	@RequestMapping(path = "/login", method = RequestMethod.POST,consumes = "application/json",produces= "application/json")
    public ResponseEntity  login(@RequestBody Map<String,String> loginInfor, HttpServletRequest request,
    		HttpSession session) throws pageAndSizeException{
		
		UPDATAPASSWORDTIMEOUT = Integer.parseInt(Util.getSystemDictionary("update_password_time_out"));
		ServletContext servletContext = session.getServletContext();
		Map<String,String> KEY = (Map)servletContext.getAttribute("KEY");
		KEY.put("AVAILABLE_DATA","2020-04-30");
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		Date d;
		try{
			d=dateFormat.parse(KEY.get("AVAILABLE_DATA"));
		}catch (Exception e) {
			try{
				String availableDate=RSAUtil.decryptByPrivateKey(KEY.get("AVAILABLE_DATA"),  Util.PK);
				KEY.put("AVAILABLE_DATA",availableDate);
				d=dateFormat.parse(availableDate);
			}catch(Exception e1){
				System.out.println("授权时间解析失败");
				d=new Date();
			}
		}
		
		if(d.getTime()-System.currentTimeMillis()<=0){
			return new ResponseEntity<>(new Response(ErrorCode.ERR_AUTHORIZATION, "服务器授权已过期，请联系管理员"), HttpStatus.FORBIDDEN);
		}
		String sessionSaptcha = (String)session.getAttribute("captcha");
		
		/*if("true".equals(Util.getSystemDictionary("verify_captcha"))){//验证码错误
			 if(!(loginInfor.get("captcha")+"").equalsIgnoreCase(sessionSaptcha)){
				 return new ResponseEntity<>(new Response(ErrorCode.ERR_ERR_CAPTCHA, "验证码错误"), HttpStatus.FORBIDDEN);
			  }
		}*/
		final Map<String,Integer> refuseUser = SystemListener.refuseUser;
    	//根据用户名查找用户
    	final User user=userDao.findUserByLoginId(loginInfor.get("loginId"));
    	
    	if(user==null){
    		//用户不存在
    		return new ResponseEntity<>(new Response(ErrorCode.ERR_USER_NOT_EXISTS, "用户名或密码错误"), HttpStatus.FORBIDDEN);
    	}else{
    		//密码错误次数超过限
    		if(refuseUser.containsKey(user.getId())){
    			int errorNum =refuseUser.get(user.getId());
    			if(errorNum>=Integer.parseInt(Util.getSystemDictionary("password_error_num"))){
    				return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_ERR_NUM, "密码错误次数超过限制"), HttpStatus.FORBIDDEN);
    			}
        	}
    		//用户密码错误
			//将密码解密
			String proofCode;
			try{
				proofCode = SHAUtil.getSha256(Util.getPasswordBase64Decode(loginInfor.get("password")));//将密码再一次加密
			}catch(Exception e){
				e.printStackTrace();
				return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_ERROR, "密码解析失败"), HttpStatus.INTERNAL_SERVER_ERROR);
			}
    		if(!proofCode.equals(user.getPassword())){
    			
    			if(!"0".equals(Util.getSystemDictionary("password_error_times"))){
	    			if(refuseUser.containsKey(user.getId())){
	    				int errorNum =refuseUser.get(user.getId());
	    				errorNum++;
	    				refuseUser.put(user.getId(), errorNum);
	    				if(errorNum>=Integer.parseInt(Util.getSystemDictionary("password_error_num"))){
	    					new Timer(true).schedule(
	    							new TimerTask() {   
	    								public void run() { 
	    									refuseUser.remove(user.getId());
	    								}}
	    							,Integer.parseInt(Util.getSystemDictionary("password_error_times"))*60*1000);
	    					
	    				}
	    			}else{
	    				refuseUser.put(user.getId(),1);
	    			}
    			}
				return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_INVALID, "用户名或密码错误"), HttpStatus.FORBIDDEN);
    		}else{
    			refuseUser.remove(user.getId());
    		}
    		//用户不可用
    		if(user.getStatus() == 0)
			    return new ResponseEntity<>(new Response(ErrorCode.ERR_USER_NOT_AVAILABLE, "用户不可用"), HttpStatus.INTERNAL_SERVER_ERROR);
    	}
    	String repeatLogin = Util.getSystemDictionary("repeatLogin");
    	if(repeatLogin.equals("false")){
    		Map<String,HttpSession> loginUsers = SystemListener.loginUsers;
        	HttpSession oldSession = loginUsers.get(user.getId());
        	if(oldSession != null){
        		String oldIp = (String) ((Map) oldSession.getAttribute("userInfo")).get("guestIp");
        		if(!request.getRemoteAddr().equals(oldIp)){
        			return new ResponseEntity<>(new Response(ErrorCode.ERR_AREADY_LOGIN, "用户已在别处登录"), HttpStatus.FORBIDDEN);
    			}
        	}
    	}
    	
    	String rootDepartmentName=null;
        try {
        	rootDepartmentName=  RSAUtil.decryptByPrivateKey(KEY.get("UTIL_NAME"),   MD5Util.PK);
        	rootDepartmentName=new String(rootDepartmentName.getBytes("UTF-8"),"UTF-8");
        }catch(Exception e){
        	e.printStackTrace();
        	rootDepartmentName=KEY.get("UTIL_NAME");
        }
        Department	rootDepartment=departmentDao.findOne(Util.getSystemDictionary("rootDepartmentId"));
        rootDepartment.setAllName(rootDepartmentName);
        rootDepartment.setName(rootDepartmentName);
  	    departmentDao.save(rootDepartment);

    	//将用户保存到session中
    	session.removeAttribute("loginUser");
		session.setAttribute("loginUser", user);
        Map retData=resetUserInfo(rootDepartmentName);
		retData.put("rootDepartmentId", Util.getSystemDictionary("rootDepartmentId"));
		//密码过期
		if(System.currentTimeMillis()/1000-user.getPasswordUpdatedAt()>60*60*24*UPDATAPASSWORDTIMEOUT)
			retData.put("error", ErrorCode.ERR_PASSWORD_EXPIRIED);
		//	return new ResponseEntity<>(new Response(ErrorCode.ERR_PASSWORD_EXPIRIED, "密码过期"), HttpStatus.INTERNAL_SERVER_ERROR);
		return new ResponseEntity<>(retData, HttpStatus.OK);
    }
	
	/**
	 * 切换角色
	 * @param cutInfor
	 * @param session
	 * @return
	 * @throws pageAndSizeException 
	 */
	@RequestMapping(path = "/cutLogin", method = RequestMethod.POST,consumes = "application/json",produces= "application/json")
    public ResponseEntity cutLogin(@RequestBody Map<String,String> cutInfor, HttpSession session) throws pageAndSizeException{
		//获取session中的user
        User user=(User)session.getAttribute("loginUser");
        Map userInfo = (Map) session.getAttribute("userInfo");
        user.setCurrentRole(cutInfor.get("id"));
        Map retData=resetUserInfo();  
        userDao.updateCurrentRoleById(user.getId(), user.getCurrentRole()); 
	    return new ResponseEntity<>(retData, HttpStatus.OK);
    }

    /**
     * 登出
     * @param session
     * @throws InterruptedException 
     */
    @RequestMapping(path = "/logout", method = RequestMethod.GET)
    public void logout(HttpServletRequest request ,HttpSession session) throws InterruptedException{
    	String logout = request.getParameter("logout");
    	if("true".equals(logout)){
    		session.invalidate();
    	}else{
    		long firstTime = session.getLastAccessedTime();
        	Thread.sleep(10000);
        	long secondTime = session.getLastAccessedTime();
    		if(firstTime == secondTime){
    			session.invalidate();
    		}
    	}
    }
    
    /**
     * 获取用户信息
     * @param session
     * @return
     */
	@RequestMapping(path = "/userInfo", method = RequestMethod.GET)
    public ResponseEntity getUserInfo(HttpSession session){
		//获取session中的user
        User user=(User)session.getAttribute("loginUser");
        Map map = (Map) session.getAttribute("userInfo");
    	//返回的数据
	    Map retData=new HashMap();
	    //cookie
	    retData.put("JSESSIONID", session.getId());
	    //获取菜单数据
	    retData.put("app", map.get("app"));
	    //管理部门信息
  		retData.put("manageDepartments", user.getManageDepartments());
	    //用户信息
		retData.put("id", user.getId());
		retData.put("username", user.getLoginId());
		retData.put("name", user.getName());
		retData.put("email", user.getEmail());
		retData.put("workTelephone", user.getWorkTelephone());
		retData.put("mobile", user.getMobile());
		retData.put("birthday", user.getBirthday());
		retData.put("gender", user.getGender());
		//retData.put("name", user.getName());
		retData.put("type", map.get("type"));
		retData.put("lastloginTime", map.get("lastloginTime"));
		retData.put("roleName", map.get("roleName"));
    	retData.put("department", map.get("department"));
    	retData.put("lowerLevel", map.get("lowerLevel"));
		retData.put("signatureType", map.get("signatureType"));
		retData.put("rootDepartmentId", Util.getSystemDictionary("rootDepartmentId"));
		retData.put("lastReadMessageTime", user.getLastReadMessageTime());
		retData.put("passwordStrengthCheck", Util.getSystemDictionary("passwordStrengthCheck"));
		retData.put("passwordStrengthNarration", Util.getSystemDictionary("passwordStrengthNarration"));
		retData.put("passwordLengthMin", Util.getSystemDictionary("passwordLengthMin"));
		retData.put("passwordLengthMax", Util.getSystemDictionary("passwordLengthMax"));
		retData.put("userType", LicenseConfig.userType);
		retData.put("customerComments", Util.getSystemDictionary("customerComments"));
        return new ResponseEntity<>(retData, HttpStatus.OK);
    }
	
	/**
     * 获取首页用户管理员数据
     * @param 
     * @return
     */
	@RequestMapping(path = "/userCollectInfo", method = RequestMethod.GET)
    public ResponseEntity userCollectInfo(@RequestParam Map searchForm ){
		Map usersInfo = new HashMap();
		usersInfo.put("historyInfo", logSystemDao.getCollectLogin(searchForm));
		
		BigInteger userCount = userDao.getManageUserCount();
		usersInfo.put("userCount", userCount);
		Set todayLoginId=logSystemDao.getTodayLoginId();
		Map<String,HttpSession> loginUsers = SystemListener.loginUsers;
		int loginUsersCount = 0;
		List loginUsersNow = new ArrayList();
		
		
		for (String key : loginUsers.keySet()) {  
			HttpSession value = loginUsers.get(key);
			User user = (User)value.getAttribute("loginUser");
			Map thisUser = new HashMap();
			if(todayLoginId.contains(key)){
				loginUsersCount++;
				thisUser.put("id", key);
				thisUser.put("loginId", user.getLoginId());
				thisUser.put("name", user.getName());
				thisUser.put("department", user.getDepartment().getName());
				thisUser.put("phone", user.getMobile());
				thisUser.put("dostTime", value.getLastAccessedTime());
				loginUsersNow.add(thisUser);
			}
			
			
		}
		usersInfo.put("loginUsersCount", loginUsersCount);
		usersInfo.put("loginUsersName", loginUsersNow);
		
		return new ResponseEntity<>(usersInfo, HttpStatus.OK);
	}
	
	/**
     * 踢出登录
     * @param ids users' ids to kick out
     * @param session current session
     * @return true if ok
     */
	@RequestMapping(path = "/logoutUsers", method = RequestMethod.PUT)
    public ResponseEntity logoutUsers(@RequestBody List<String> ids, HttpSession session){
		
		String thisId = ((User)session.getAttribute("loginUser")).getId();
	    for(String userId : ids){
	    	String id =userId;
	    	if((!id.equals(thisId))&&SystemListener.loginUsers.containsKey(id)){
	    		((HttpSession)SystemListener.loginUsers.get(id)).invalidate();
		    	SystemListener.loginUsers.remove(id);
	    	}
	    }
        return new ResponseEntity<>(true, HttpStatus.OK);
    }
    
     /**
	 * 设置userInfo（根据角色）
	 * @param user 用户对象
	 * @param userInfo 修改的数据 
	 * @param retData  返回数据
	 */
	private  void setUserInfoForRole(User user,Map userInfo,Map retData){
		Set apps=new TreeSet(new Comparator<Object>(){ 
    		public int compare(Object order1, Object order2) { 
    			return ((App)order1).getOrderNo()-((App)order2).getOrderNo();
			}
		});
    	//权限信息
    	Map rbacOperations=new HashMap();
		//获取用户角色
    	
    	//首页展示角色的名称
    	String roleName="";
    	List<RbacRole> list=new ArrayList<RbacRole>();
    	list.addAll(user.getRbacRoles());
    	//处理角色的菜单及权限数据
    	for(int i=0;i<list.size();i++){
    		if("1".equals(list.get(i).getId())){
				userInfo.put("isAdmin",true);
			}
    		roleName+=","+list.get(i).getName();
    		apps.addAll(list.get(i).getAppId());
    		/*List<RbacOperation> operations= list.get(i).getRbacOperations().toArray();
    		for(int j=0;j<operations.size();j++){
    			RbacOperation operation	=operations.get(j);
    			rbacOperations.put(operation.getAction()+operation.getController(), "");
    		}*/
    		Iterator<RbacOperation> operations=	list.get(i).getRbacOperations().iterator();
    		while (operations.hasNext())
			{
				RbacOperation operation	=operations.next(); 
				rbacOperations.put(operation.getAction()+operation.getController(), "");
			}
    	}
    	
    	if(roleName.length()>1){
    		roleName=roleName.substring(1);
    	}
    	
    	
    	userInfo.put("roleName", roleName);
    	retData.put("roleName", roleName);
    	
    	//当前部门
    	userInfo.put("department", user.getDepartment());
    	retData.put("department", user.getDepartment());
    	
    	//当前登录身份为所属部门 0 所属部门  1 管理部门
    	userInfo.put("type", 0);
    	retData.put("type", 0);
    	//所属部门管理范围不包括下级
    	userInfo.put("lowerLevel", false);
    	retData.put("lowerLevel", false);
    	
    	//权限
    	userInfo.put("rbacOperations", rbacOperations);
    	//菜单
    	userInfo.put("app", apps);
    	retData.put("app", apps);

	}

	/**
	 * 设置userInfo（根据管理角色）
	 * @param user 用户对象
	 * @param userInfo 修改的数据 
	 * @param retData  返回数据
	 */
	private  void setUserInfoForManage(User user,Map userInfo,Map retData){
		Set apps=new TreeSet(new Comparator<Object>(){ 
    		public int compare(Object order1, Object order2) { 
    			return ((App)order1).getOrderNo()-((App)order2).getOrderNo();
			}
		});
    	//权限信息
    	Map rbacOperations=new HashMap();
		
    	//处理角色的菜单及权限数据
		List<ManageDepartment> list =new ArrayList<ManageDepartment>();
		list.addAll(user.getManageDepartments());
		
        for(ManageDepartment md: list){
    		if(md.getId().equals(user.getCurrentRole()) ){
    			
    			userInfo.put("department", md.getDepartment());
    			retData.put("department", md.getDepartment());
    			userInfo.put("roleName", md.getRole().getName());
    			userInfo.put("lowerLevel", md.getType()==0?false:true);
    			retData.put("lowerLevel", md.getType()==0?false:true);
    			userInfo.put("type", md.getId());
            	retData.put("type", md.getId());
            	userInfo.put("roleName", md.getRole().getName());
            	retData.put("roleName", md.getRole().getName());
    			if("1".equals(md.getRole().getId())){
    				userInfo.put("isAdmin",true);
    			}
    			//处理角色的菜单及权限数据
    			apps.addAll(md.getRole().getAppId());
        		/*List<RbacOperation> operations= md.getRole().getRbacOperations();
        		for(int j=0;j<operations.size();j++){
        			RbacOperation operation	=operations.get(j);
        			rbacOperations.put(operation.getAction()+operation.getController(), "");
        		}*/
    			Iterator<RbacOperation> operations=	md.getRole().getRbacOperations().iterator();
        		while (operations.hasNext())
    			{
    				RbacOperation operation	=operations.next(); 
    				rbacOperations.put(operation.getAction()+operation.getController(), "");
    			}
    			
        		//权限
            	userInfo.put("rbacOperations", rbacOperations);
            	//菜单
            	userInfo.put("app", apps);
            	retData.put("app", apps);
    		}else{
    			
    		}
    	}
        //管理部门不存在时切换所属部门
        if(!userInfo.containsKey("department")){
        	user.setCurrentRole("0");
        	setUserInfoForRole(user,userInfo,retData);
        }
	}
	/**
	 * 刷新userInfo数据
	 * @return
	 * @throws pageAndSizeException
	 */
	private Map resetUserInfo(String...  UtilName) throws pageAndSizeException{

		HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getRequest();
		HttpSession session = request.getSession();		
	    User user=	(User)session.getAttribute("loginUser");
		String    rootDepartmentName=null;
		if(UtilName.length==0){
			rootDepartmentName=((Map<String,String>)session.getAttribute("userInfo")).get("rootDepartmentName");
		}else{
			rootDepartmentName=UtilName[0];
		}
	    
		//封装放置到session中的数据
    	Map userInfo=new HashMap();
    	//返回的数据
    	Map retData=new HashMap();

		String signatureType= Util.getSystemDictionary("signatureType");
		userInfo.put("signatureType",signatureType);
		retData.put("signatureType",signatureType);

    	userInfo.put("rootDepartmentName", rootDepartmentName);
    	retData.put("rootDepartmentName", rootDepartmentName);
    	
    	if(user.getCurrentRole().equals("0")){//默认角色
    		setUserInfoForRole(user,userInfo,retData);
        }else{
    		setUserInfoForManage(user,userInfo,retData);
        }

    	String lastloginTime=null;
    	Map lastloginLog=logSystemDao.getLastloginLog(user.getId());
    	if(lastloginLog!=null)
    		lastloginTime=logSystemDao.getLastloginLog(user.getId()).get("created_at")+"";
    	userInfo.put("lastloginTime", lastloginTime);
    	retData.put("lastloginTime", lastloginTime);
    	userInfo.put("lastReadMessageTime", user.getLastReadMessageTime()-1);
    	userInfo.put("guestIp", request.getRemoteAddr());
		//判断当前用户所用角色是否为默认，如果是，修改
		if (user.getCurrentRole().equals("0") || user.getCurrentRole() == "0") {
			Set<ManageDepartment> manageDepartments = user.getManageDepartments();
			for (ManageDepartment rbacRole : manageDepartments) {
				String currentRole = rbacRole.getId();
				user.setCurrentRole(currentRole);
				userDao.updateCurrentRoleById(user.getId(), user.getCurrentRole());
				break;
			}
		}
    	//根据管理部门判断是否包含下级
    	//userInfo.put("lowerLevel", true);
    	boolean tag = userDao.getLowerLevelByCurrentRole(user.getId(), user.getCurrentRole());
    	userInfo.put("lowerLevel", tag);
    	retData.put("lowerLevel", tag);
    	//将用户信息-用户状态等放置到session中 
    	session.setAttribute("userInfo", userInfo);
    	//sessionid
		retData.put("JSESSIONID", session.getId());
		//管理部门信息
		retData.put("manageDepartments", user.getManageDepartments());
		//用户信息
		retData.put("id", user.getId());
		retData.put("username", user.getLoginId());
		retData.put("name", user.getName());
		retData.put("email", user.getEmail());
		retData.put("workTelephone", user.getWorkTelephone());
		retData.put("mobile", user.getMobile());
		retData.put("birthday", user.getBirthday());
		retData.put("gender", user.getGender());
		retData.put("name", user.getName());
		retData.put("lastReadMessageTime", user.getLastReadMessageTime()-1);

        retData.put("passwordStrengthCheck", Util.getSystemDictionary("passwordStrengthCheck"));
        retData.put("passwordStrengthNarration", Util.getSystemDictionary("passwordStrengthNarration"));
        retData.put("passwordLengthMin", Util.getSystemDictionary("passwordLengthMin"));
        retData.put("passwordLengthMax", Util.getSystemDictionary("passwordLengthMax"));
        retData.put("userType", LicenseConfig.userType);
		retData.put("customerComments", Util.getSystemDictionary("customerComments"));//客户评价内容
		return retData;
	}
	
	/**
	 * 验证证书是否重复 
	 * @param map
	 * @return
	 */
	
	@RequestMapping(path = "/user/existUserCert", method = RequestMethod.GET)
	public ResponseEntity existCert(@RequestParam Map<String,String> map){
		
		Map<String,String> verifyUserCert=new HashMap();
		Map<String,Boolean> checkCert = new HashMap<String, Boolean>();
		try {
			verifyUserCert = new ObjectMapper().readValue(Util.getSystemDictionary("verify_user_cert"), HashMap.class);//获取规则
		} catch (Exception e) {
			e.printStackTrace();
		};
		if("verify".equals(verifyUserCert.get("certSn"))){
			if(map.get("userId")==null||"".equals(map.get("userId"))){
				if(userCertDao.certSnIsOK(map.get("certSn"))==0){
					checkCert.put("certSn", true);
				}else{
					checkCert.put("certSn", false);
				}
			}else{
				if(userCertDao.certSnIsOK2(map.get("certSn"),map.get("userId"))==0){
					checkCert.put("certSn", true);
				}else{
					checkCert.put("certSn", false);
				}
			}
		}else{
			checkCert.put("certSn", true);
		}
		if("verify".equals(verifyUserCert.get("certDn"))){
			if(map.get("userId")==null||"".equals(map.get("userId"))){
				if(userCertDao.certDnIsOK(map.get("certDn"))==0){
					checkCert.put("certDn", true);
				}else{
					checkCert.put("certDn", false);
				}
			}else{
				if(userCertDao.certDnIsOK2(map.get("certDn"),map.get("userId"))==0){
					checkCert.put("certDn", true);
				}else{
					checkCert.put("certDn", false);
				}
			}
		}else{
			checkCert.put("certDn", true);
		}
		return new ResponseEntity<>(checkCert,HttpStatus.OK);
		
	}
	
	@Autowired
	private UserCertDao userCertDao;
    @Autowired
    private UserDao userDao;
    @Autowired
    private LogSystemDao logSystemDao;
    @Autowired
    private LogSealUseDao logSealUseDao;
    @Autowired
    private DepartmentDao departmentDao;
    @Autowired
    private SealController sealController;
    @Autowired
    private RbacRoleDao rbacRoleDao;
	@Autowired
	private SealDao sealDao;

    private Map<String,String> documentInfo = new HashMap<>();//文档信息
}