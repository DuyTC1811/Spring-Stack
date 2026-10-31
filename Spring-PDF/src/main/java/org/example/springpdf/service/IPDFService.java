package org.example.springpdf.service;

public interface IPDFService {
    byte[] createPDF();

    void createImagePDF(String inImageFilename, String outFilename);
}
