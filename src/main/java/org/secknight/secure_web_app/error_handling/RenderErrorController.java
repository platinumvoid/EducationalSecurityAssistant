package org.secknight.secure_web_app.error_handling;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.httpclient.HttpStatus;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Renders Http Status Codes with the appropriate HTML page
 */
@Controller
public class RenderErrorController implements ErrorController{

	@Override
	public String getErrorPath() {
		return "/error";
	}
	
	@RequestMapping("/error")
	public String handleError(HttpServletRequest request, Model model) {
		Object status =request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
		if (status!=null) {		
			model.addAttribute("errorCode", Integer.valueOf(status.toString()));
			model.addAttribute("errorMessage", HttpStatus.getStatusText(Integer.parseInt(status.toString())));
		}else {
			model.addAttribute("errorCode","Unknown");
			model.addAttribute("errorMessage","Unknown State");
		}
		return "error";
	}
}
