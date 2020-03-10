package com.dianju.signatureServer;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.dianju.core.Response;
import com.dianju.core.Util;
//import com.mysql.jdbc.util.Base64Decoder;
import com.dianju.core.models.UUIDReduce;

import sun.misc.BASE64Decoder;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@RestController
public class AutoPdfSealController {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private DocumentCreating documentCreating;

    /**
     * 获取合成后的模版文件
     * @param name 文件名称(带扩展名)
     * @return
     */
    @RequestMapping(path = "/file/{subdir}/{path}", method = RequestMethod.GET, produces = MediaType.APPLICATION_ATOM_XML_VALUE)
    public ResponseEntity getFile(@RequestParam String name, @PathVariable String subdir, @PathVariable String path, HttpServletResponse response){
        log.info("下载文件，调用/file/{subdir}/{path}接口");
        try {
            response.setHeader("content-disposition","attachment;filename=" + name);
            String filePath = Util.getSystemDictionary("upload_path")+"/"+subdir+"/"+path+"/";//合成后的模版存储路径
            System.out.println(filePath + name);
            InputStream in = new FileInputStream(filePath + name);
            int len = 0;
            byte[] buffer = new byte[1024];
            OutputStream out = response.getOutputStream();
            while((len = in.read(buffer)) > 0) {
                out.write(buffer,0, len);
            }
            in.close();
            return null;
        } catch (FileNotFoundException e) {
            log.info(e.toString());
            return new ResponseEntity<>("wrong-没有找到该文件", HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(path = "/file/{path}", method = RequestMethod.GET, produces = MediaType.APPLICATION_ATOM_XML_VALUE)
    public ResponseEntity getFile1(@RequestParam String name,@PathVariable String path, HttpServletResponse response){
        log.info(name+":::"+path);
        return getFile(name, "", path, response);
    }
	
	/**
	 * 服务端盖章
	 * @param xmlStr
	 * @return 
	 */
	@RequestMapping(path = "/sealAutoPdf", method = RequestMethod.POST, produces = "application/xml")
	public ResponseEntity sealAutoPdf(@RequestParam String xmlStr,HttpServletRequest request){
		try {
			//组装数据成xml形式
			long beginTime=new Date().getTime();
			String result = ((DocumentComposition)Util.getBean("documentComposition")).sealAutoPdf(xmlStr, DocumentComposition.SyntheticPattern.AddSeal,beginTime,request);
			return new ResponseEntity<>(result,HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}


	/**
	 * 服务端盖章以json的形式进行传参
	 * @param xmlStr
	 * @return
	 */
	@RequestMapping(path = "/getElectronicSignatureAPI", method = RequestMethod.POST, produces = "application/xml")
	public ResponseEntity getElectronicSignatureAPI(@RequestParam String xmlStr,HttpServletRequest request){
		try {
			//组装数据成xml形式
			long beginTime=new Date().getTime();
			xmlStr  = getRequestXmlStr(xmlStr);
			String result = ((DocumentComposition)Util.getBean("documentComposition")).sealAutoPdf(xmlStr, DocumentComposition.SyntheticPattern.AddSeal,beginTime,request);
			return new ResponseEntity<>(result,HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	/**
	 * 服务器 文件转换wordToPdf
	 * @param xmlStr
	 * @param request
	 * @return
	 */
	@RequestMapping(path = "/wordToPdf", method = RequestMethod.POST, produces = "application/xml")
	public ResponseEntity wordToPdf(@RequestParam String xmlStr,HttpServletRequest request){
		try {
			long beginTime=new Date().getTime();
			String result = ((DocumentComposition)Util.getBean("documentComposition")).wordToPdf(xmlStr,beginTime,request);
			return new ResponseEntity<>(result,HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
	
	
	
	/**
	 * 服务端盖章(aip)
	 * @param xmlStr
	 * @return 
	 */
	@RequestMapping(path = "/sealAutoAip", method = RequestMethod.POST, produces = "application/xml")
	public ResponseEntity sealAutoAip(@RequestParam String xmlStr,HttpServletRequest request){
		try {
			long beginTime=new Date().getTime();
			String result = ((DocumentComposition)Util.getBean("documentComposition")).sealAutoAip(xmlStr, DocumentComposition.SyntheticPattern.AddSeal,beginTime,request);
			return new ResponseEntity<>(result,HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
	
	
	/**
	 * 服务端文档验证
	 * @param xmlStr
	 * @return 
	 */
	@RequestMapping(path = "/pdfVarify", method = RequestMethod.POST, produces = "application/xml")
	public ResponseEntity pdfVarify(@RequestParam String xmlStr,HttpServletRequest request){
		try {
			long beginTime=new Date().getTime();
			String result = ((DocumentComposition)Util.getBean("documentComposition")).pdfVarify(xmlStr, beginTime+"",request);
			return new ResponseEntity<>(result,HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}



	/**
	 * 文档合成
	 * @param xmlStr
	 * @return
	 */
	@RequestMapping(path = "/modelAutoMerger", method = RequestMethod.POST, produces = "application/xml")
	public ResponseEntity modelAutoMerger(@RequestParam String xmlStr,HttpServletRequest request){
		try {
			long beginTime=new Date().getTime();
			String result = ((DocumentComposition)Util.getBean("documentComposition")).sealAutoPdf(xmlStr, DocumentComposition.SyntheticPattern.NoSeal,beginTime,request);
			return new ResponseEntity<>(result,HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@RequestMapping(path = "/documentToImg/{requestNo}", method = RequestMethod.POST, produces = "application/json", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity documentToImg(@PathVariable String requestNo, HttpServletRequest request){
		try {
			MultipartFile imageFile = Util.getUploadFile(request).get(0);
			byte[] fileData = imageFile.getBytes();
			int pageCount = documentCreating.documentToImg(fileData, requestNo);
			return new ResponseEntity<>(pageCount, HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	/**
	 * 下载文档然后转成图片
	 * @param info fileName 文件名称
	 *             fileUrl 文档url地址
	 *             requestNo 时间戳
	 * @return
	 */
	@RequestMapping(path = "/documentAutoToImgs",method = RequestMethod.GET)
	public ResponseEntity documentAutoToImg(@RequestParam Map info){
		String fileName = (String) info.get("fileName");
		String fileUrl = (String) info.get("fileUrl");
		String requestNo =(String) info.get("requestNo");
		if (Util.isBlank(fileUrl) || Util.isBlank(fileName)){
			return new ResponseEntity<>(new Response(404,"缺少参数"), HttpStatus.BAD_REQUEST);
		}

		String saveFileName = Util.getSystemDictionary("upload_path")+"/"+fileName;

		HttpClient client = new HttpClient();
		GetMethod get = null;
		BufferedOutputStream outStream=null;

		try {
			get = new GetMethod(fileUrl);
			int i=client.executeMethod(get);
			log.info("http连接i----------"+i);
			if (200 == i) {
				outStream = new BufferedOutputStream(new FileOutputStream(saveFileName));
				outStream.write(get.getResponseBody());
				outStream.flush();
				log.info(fileName+":http文档下载成功 "+saveFileName);

				File file =new File(saveFileName);
				FileInputStream fis = new FileInputStream(file);
				byte[] fileData = new byte[(int) file.length()];
				fis.read(fileData);
				fis.close();
				int pageCount = documentCreating.documentToImg(fileData, requestNo);
				return new ResponseEntity<>(pageCount, HttpStatus.OK);

			}else{
				log.info(fileName+":http请求错误 地址:"+fileUrl+" http返回值:"+i);
				return new ResponseEntity<>(new Response(404,"http请求错误 地址:"+fileUrl+" http返回值:"+i), HttpStatus.BAD_REQUEST);
			}
		} catch (Exception e) {
			e.printStackTrace();
			log.info("服务端异常......");
			return new ResponseEntity<>(new Response(500,"服务端异常"), HttpStatus.INTERNAL_SERVER_ERROR);
		}finally{
			try {
				outStream.close();
			} catch (Exception e) {

			}
			get.releaseConnection();
			client.getHttpConnectionManager().closeIdleConnections(0);
		}
	}
	
	
	/**
	 * 下载base64格式文档然后转成图片
	 * @param info fileName 文件名称
	 *             fileBase64 文档base64数据
	 *             requestNo 时间戳
	 * @return
	 */
	@RequestMapping(path = "/documentBase64AutoToImgs",method = RequestMethod.POST, produces = "application/json")
	public ResponseEntity documentBase64AutoToImg(@RequestBody Map info){
		String fileName = (String) info.get("fileName");
		String fileBase64 =(String) info.get("fileBase64");
		String requestNo =(String) info.get("requestNo");
		if (Util.isBlank(fileBase64) || Util.isBlank(fileName)||Util.isBlank(fileBase64)){
			return new ResponseEntity<>(new Response(404,"缺少参数"), HttpStatus.BAD_REQUEST);
		}
		String saveFileName = Util.getSystemDictionary("upload_path")+"/"+fileName;
			String dirS=Util.getSystemDictionary("upload_path");
			File dir=new File(dirS);
			if(!dir.exists()||!dir.isDirectory()){
				dir.mkdirs();
			}
			try {
					 byte[] buffer;
						buffer = new BASE64Decoder().decodeBuffer(fileBase64);
					 FileOutputStream out = new FileOutputStream(saveFileName);  
					 out.write(buffer);  
					 out.close();  
			} catch (IOException e) {
				e.printStackTrace();
				return new ResponseEntity<>(new Response(500,"文档保存服务器失败"), HttpStatus.BAD_REQUEST);
				
			}  
			File file =new File(saveFileName);
			FileInputStream fis;
			int pageCount = 0;
			try {
				fis = new FileInputStream(file);
			byte[] fileData = new byte[(int) file.length()];
			fis.read(fileData);
			fis.close();
			pageCount = documentCreating.documentToImg(fileData, requestNo);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				return new ResponseEntity<>(new Response(404,"文档转换图片异常"), HttpStatus.BAD_REQUEST);
			} catch (IOException e) {
				e.printStackTrace();
				return new ResponseEntity<>(new Response(404,"文档转换图片异常"), HttpStatus.BAD_REQUEST);
			}
		return new ResponseEntity<>(pageCount, HttpStatus.OK);
	}

	@RequestMapping(path = "/checkImg/{requestNo}/{imgNo}", method = RequestMethod.GET, produces = "application/json")
	public ResponseEntity checkImg(@PathVariable String requestNo, @PathVariable int imgNo, HttpServletRequest request){
		try {
		    boolean isLoaded = DJPdfToImgUtil.loadImgMap.get(requestNo)[imgNo];
		    if(!isLoaded){
                DJPdfToImgUtil.viewImgMap.put(requestNo, imgNo);
            }
			return new ResponseEntity<>(isLoaded, HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@RequestMapping(path = "/testBD", method = RequestMethod.GET,produces = "application/octet-stream")
	public ResponseEntity testBD(){
		return new ResponseEntity<>("testBD",HttpStatus.OK);
		
	}


    /**
     * pdf添加水印
     * @param xmlStr
     * @return
     */
    @RequestMapping(path = "/addWatermarkToPdf", method = RequestMethod.POST, produces = "application/xml")
    public ResponseEntity addWatermarkToPdf(@RequestParam String xmlStr,HttpServletRequest request){
        try {
            long beginTime=new Date().getTime();
            String result = ((DocumentComposition)Util.getBean("documentComposition")).addWatermarkToPdf(xmlStr,beginTime+"",request);
            return new ResponseEntity<>(result,HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("wrong", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    /**
     * 文件转图片
     * @param xmlStr
     * @param request
     * @param response
     */
    @RequestMapping(path = "/fileToPicture", method = RequestMethod.POST, produces = "application/xml")
    public void fileToPicture(@RequestParam String xmlStr,HttpServletRequest request,HttpServletResponse response){
        try {
            String result = ((DocumentComposition)Util.getBean("documentComposition")).fileToPicture(xmlStr, UUIDReduce.uuid(), request);
            response.setCharacterEncoding("utf-8");
            response.getWriter().print(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * 文件转图片
     * @param
     * @param
     * @param
     * @param request
     * @param response
     */
    
    @RequestMapping(path = "/fileToPicturetest", method = RequestMethod.POST, produces = "application/xml")
    public void fileToPicturetest(@RequestParam String FILE_NO,@RequestParam String FILE_PATH,@RequestParam String PICTURE_WIDTH,@RequestParam String PICTURE_TYPE,HttpServletRequest request,HttpServletResponse response){
        try {
            int result = ((DocumentComposition)Util.getBean("documentComposition")).fileToPictureTest(FILE_NO,FILE_PATH, PICTURE_WIDTH,PICTURE_TYPE,UUIDReduce.uuid(), request);
            response.setCharacterEncoding("utf-8");
            response.getWriter().print(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * 文件转图片
     * @param xmlStr
     * @param request
     * @param response
     */
/*    @RequestMapping(path = "/fileToPicturetest", method = RequestMethod.POST, produces = "application/xml")
    public void fileToPicturetest(@RequestParam String xmlStr,HttpServletRequest request,HttpServletResponse response){
    	try {
    		int result = ((DocumentComposition)Util.getBean("documentComposition")).fileToPictureTest(xmlStr, UUIDReduce.uuid(), request);
    		response.setCharacterEncoding("utf-8");
    		response.getWriter().print(result);
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    }
*/     
    /**
     * 合成签名接口
     * @param fileName
     * @param filePath
     * @param H5Data
     * @param request
     * @param response
     */
   @RequestMapping(path = "/h5Merge", method = RequestMethod.POST, produces = "application/xml")
    public void H5Merge(@RequestParam String fileName,@RequestParam String filePath,@RequestParam String H5Data,HttpServletRequest request,HttpServletResponse response){
        try {
            String result = ((DocumentComposition)Util.getBean("documentComposition")).Merge(fileName,filePath,H5Data,request);
            response.setCharacterEncoding("utf-8");
            response.getWriter().print(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //请求参数解析
	public     String   getRequestXmlStr(String  str) {
		String  xmlStr= "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n" +
				"<SEAL_DOC_REQUEST>\n" +
				"<BASE_DATA>\n" +
				"<SYS_ID>10086</SYS_ID>\n" +
				"<SYS_PWD>123456</SYS_PWD>\n" +
				"</BASE_DATA>\n" +
				"<META_DATA>\n" +
				"<!--是否模板合并-->\n" +
				"<IS_MERGER>false</IS_MERGER>\n" +
				"</META_DATA>\n" +
				"<FILE_LIST>\n" ;
		        JSONObject obj = JSONObject.parseObject(str);
				//对数组的解析
				JSONArray pdfUrlList = obj.getJSONArray("pdfUrlList");//pdf地址的集合
				System.out.println("pdfUrlList：");
				for (int i = 0; i < pdfUrlList.size(); i++) {
					String s = (String) pdfUrlList.get(i);
					xmlStr +="<TREE_NODE>\n" +
							"<FILE_NO>ceshi.pdf</FILE_NO>\n" +
							"<CJ_TYPE>file</CJ_TYPE>\n" +
							"<!--0:http 1:ftp-->\n" +
							"<REQUEST_TYPE>0</REQUEST_TYPE>\n" +
							//"<FILE_PATH>http://127.0.0.1:8080/ESS/jian.pdf</FILE_PATH>\n" +
							"<FILE_PATH>"+s+"</FILE_PATH>\n" +
							"<!--是否模板合并-->\n" +
							"<IS_MERGER>false</IS_MERGER>\n" +
							"<!--是否添加二维码-->\n" +
							"<IS_CODEBAR>false</IS_CODEBAR>\n" +
							"<DOC_TYPE>pdf</DOC_TYPE>\n" +
							"<!--规则类型0：按规则号盖章，1：按规则信息盖章-->\n" +
							"<RULE_TYPE>0</RULE_TYPE>\n" +
							"<!--规则号，多个规则用逗号隔开-->\n" +
							"<RULE_NO>001</RULE_NO>\n" +
							"</TREE_NODE>\n" ;
				}
		       xmlStr +="</FILE_LIST>\n" +
				"</SEAL_DOC_REQUEST>";
		return xmlStr;
	}



	//返回参数解析
	public     String   getResponseXmlStr(String  str) {
		String  xmlStr= "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n" +
				"<SEAL_DOC_REQUEST>\n" +
				"<BASE_DATA>\n" +
				"<SYS_ID>10086</SYS_ID>\n" +
				"<SYS_PWD>123456</SYS_PWD>\n" +
				"</BASE_DATA>\n" +
				"<META_DATA>\n" +
				"<!--是否模板合并-->\n" +
				"<IS_MERGER>false</IS_MERGER>\n" +
				"</META_DATA>\n" +
				"<FILE_LIST>\n" ;
		JSONObject obj = JSONObject.parseObject(str);
		//对数组的解析
		JSONArray pdfUrlList = obj.getJSONArray("pdfUrlList");//pdf地址的集合
		System.out.println("pdfUrlList：");
		for (int i = 0; i < pdfUrlList.size(); i++) {
			String s = (String) pdfUrlList.get(i);
			xmlStr +="<TREE_NODE>\n" +
					"<FILE_NO>ceshi.pdf</FILE_NO>\n" +
					"<CJ_TYPE>file</CJ_TYPE>\n" +
					"<!--0:http 1:ftp-->\n" +
					"<REQUEST_TYPE>0</REQUEST_TYPE>\n" +
					"<FILE_PATH>http://127.0.0.1:8080/ESS/jian.pdf</FILE_PATH>\n" +
					"<!--是否模板合并-->\n" +
					"<IS_MERGER>false</IS_MERGER>\n" +
					"<!--是否添加二维码-->\n" +
					"<IS_CODEBAR>false</IS_CODEBAR>\n" +
					"<DOC_TYPE>pdf</DOC_TYPE>\n" +
					"<!--规则类型0：按规则号盖章，1：按规则信息盖章-->\n" +
					"<RULE_TYPE>0</RULE_TYPE>\n" +
					"<!--规则号，多个规则用逗号隔开-->\n" +
					"<RULE_NO>001</RULE_NO>\n" +
					"</TREE_NODE>\n" ;
		}
		xmlStr +="</FILE_LIST>\n" +
				"</SEAL_DOC_REQUEST>";
		return xmlStr;
	}
    
}
