package org.secknight.secure_web_app.controllers.vulnerabilities;

import javax.validation.constraints.NotNull;

public class Input {
    @NotNull
    private String input;
    public void setInput(String input) {this.input = input;}
    public String getInput() {return input;}
}
