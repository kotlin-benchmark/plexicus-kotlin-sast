package com.plexicus.demo.controller

import com.plexicus.demo.model.DataRequest
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import org.springframework.web.servlet.ModelAndView
import org.xml.sax.InputSource
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.ObjectInputStream
import java.io.StringReader
import java.util.Base64
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

@RestController
@RequestMapping("/data")
class DataController(private val restTemplate: RestTemplate = RestTemplate()) {

    /**
     * VULNERABILITY: Insecure deserialization — raw ObjectInputStream over an
     * attacker-controlled byte stream. PLEXICUS-RULE: SPRING-DESERIALIZE-OIS
     */
    @PostMapping("/deserialize")
    fun deserialize(@RequestBody req: DataRequest): ResponseEntity<String> {
        val bytes = Base64.getDecoder().decode(req.payloadBase64.orEmpty())
        val ois = ObjectInputStream(ByteArrayInputStream(bytes))
        val obj = ois.readObject()
        ois.close()
        return ResponseEntity.ok("deserialized=${obj.javaClass.name}")
    }

    /**
     * VULNERABILITY: XXE — DocumentBuilderFactory without disabling external
     * entities or DTDs. PLEXICUS-RULE: SPRING-XXE-DOCUMENT-BUILDER
     */
    @PostMapping("/xml")
    fun parseXml(@RequestBody req: DataRequest): ResponseEntity<String> {
        val dbf = DocumentBuilderFactory.newInstance()
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(req.xml.orEmpty())))
        return ResponseEntity.ok("root=${doc.documentElement.tagName}")
    }

    /**
     * VULNERABILITY: SSRF — server-side fetch of attacker-controlled URL.
     * PLEXICUS-RULE: SPRING-SSRF-RESTTEMPLATE
     */
    @GetMapping("/fetch")
    fun fetch(@RequestParam url: String): ResponseEntity<String> {
        val body = restTemplate.getForObject(url, String::class.java) ?: ""
        return ResponseEntity.ok(body)
    }

    /**
     * VULNERABILITY: Server-side template injection — Thymeleaf template name
     * taken directly from the request. PLEXICUS-RULE: SPRING-SSTI-THYMELEAF-TEMPLATE
     */
    @GetMapping("/render")
    fun render(@RequestParam template: String): ModelAndView {
        return ModelAndView(template)
    }

    /**
     * VULNERABILITY: Zip slip — entry name resolved against `dest` without
     * canonicalization. PLEXICUS-RULE: SPRING-ZIP-SLIP
     */
    @PostMapping("/extract")
    fun extract(@RequestBody req: DataRequest): ResponseEntity<List<String>> {
        val src = File(req.archivePath ?: "/tmp/in.zip")
        val dest = File("/tmp/extracted")
        dest.mkdirs()
        val extracted = mutableListOf<String>()
        ZipInputStream(src.inputStream()).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val outFile = File(dest, entry.name)
                outFile.parentFile?.mkdirs()
                FileOutputStream(outFile).use { fos ->
                    zis.copyTo(fos)
                }
                extracted += outFile.absolutePath
                entry = zis.nextEntry
            }
        }
        return ResponseEntity.ok(extracted)
    }
}
