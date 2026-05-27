package com.plexicus.demo.controller

import org.springframework.core.io.FileSystemResource
import org.springframework.core.io.Resource
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import java.nio.file.Files
import java.nio.file.Paths

@RestController
@RequestMapping("/files")
class FileController {

    private val uploadDir: String = "/tmp/uploads"

    /**
     * VULNERABILITY: Path traversal — caller-controlled `name` joined into the
     * upload directory without normalization. PLEXICUS-RULE: SPRING-PATH-TRAVERSAL
     */
    @PostMapping("/upload")
    fun upload(@RequestParam name: String, @RequestParam("file") file: MultipartFile): String {
        val target = Paths.get(uploadDir, name)
        Files.createDirectories(target.parent)

        // VULNERABILITY: No extension / content-type allow-list — any binary is
        // accepted. PLEXICUS-RULE: SPRING-UPLOAD-UNRESTRICTED
        Files.write(target, file.bytes)
        return "stored=${target.toAbsolutePath()}"
    }

    /**
     * VULNERABILITY: Serves any file from disk with `inline` disposition and a
     * generic content type — drive-by downloads / reflected file download.
     * PLEXICUS-RULE: SPRING-FILE-NO-CONTENT-DISPOSITION
     */
    @GetMapping("/get")
    fun get(@RequestParam name: String): ResponseEntity<Resource> {
        val path = Paths.get(uploadDir, name)
        val resource = FileSystemResource(path.toFile())
        val headers = HttpHeaders().apply {
            contentType = MediaType.APPLICATION_OCTET_STREAM
            // Note: no Content-Disposition header set — browsers may render
            // or auto-execute returned content.
        }
        return ResponseEntity.ok().headers(headers).body(resource)
    }
}
