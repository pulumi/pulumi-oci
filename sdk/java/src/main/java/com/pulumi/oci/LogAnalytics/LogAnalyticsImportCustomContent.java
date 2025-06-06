// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.LogAnalytics.LogAnalyticsImportCustomContentArgs;
import com.pulumi.oci.LogAnalytics.inputs.LogAnalyticsImportCustomContentState;
import com.pulumi.oci.LogAnalytics.outputs.LogAnalyticsImportCustomContentChangeList;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Log Analytics Import Custom Content resource in Oracle Cloud Infrastructure Log Analytics service.
 * 
 * Imports the specified custom content from the input in zip format.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.LogAnalytics.LogAnalyticsImportCustomContent;
 * import com.pulumi.oci.LogAnalytics.LogAnalyticsImportCustomContentArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testLogAnalyticsImportCustomContent = new LogAnalyticsImportCustomContent("testLogAnalyticsImportCustomContent", LogAnalyticsImportCustomContentArgs.builder()
 *             .importCustomContentFile(logAnalyticsImportCustomContentImportCustomContentFile)
 *             .namespace(logAnalyticsImportCustomContentNamespace)
 *             .expect(logAnalyticsImportCustomContentExpect)
 *             .isOverwrite(logAnalyticsImportCustomContentIsOverwrite)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * Import is not supported for LogAnalyticsImportCustomContent
 * 
 */
@ResourceType(type="oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent")
public class LogAnalyticsImportCustomContent extends com.pulumi.resources.CustomResource {
    /**
     * LogAnalyticsImportCustomChangeList
     * 
     */
    @Export(name="changeLists", refs={List.class,LogAnalyticsImportCustomContentChangeList.class}, tree="[0,1]")
    private Output<List<LogAnalyticsImportCustomContentChangeList>> changeLists;

    /**
     * @return LogAnalyticsImportCustomChangeList
     * 
     */
    public Output<List<LogAnalyticsImportCustomContentChangeList>> changeLists() {
        return this.changeLists;
    }
    /**
     * The content name.
     * 
     */
    @Export(name="contentName", refs={String.class}, tree="[0]")
    private Output<String> contentName;

    /**
     * @return The content name.
     * 
     */
    public Output<String> contentName() {
        return this.contentName;
    }
    /**
     * A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is &#34;100-Continue&#34; (case-insensitive).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="expect", refs={String.class}, tree="[0]")
    private Output<String> expect;

    /**
     * @return A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is &#34;100-Continue&#34; (case-insensitive).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> expect() {
        return this.expect;
    }
    /**
     * The field names.
     * 
     */
    @Export(name="fieldNames", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> fieldNames;

    /**
     * @return The field names.
     * 
     */
    public Output<List<String>> fieldNames() {
        return this.fieldNames;
    }
    /**
     * Path to the file to upload which contains the custom content.
     * 
     */
    @Export(name="importCustomContentFile", refs={String.class}, tree="[0]")
    private Output<String> importCustomContentFile;

    /**
     * @return Path to the file to upload which contains the custom content.
     * 
     */
    public Output<String> importCustomContentFile() {
        return this.importCustomContentFile;
    }
    /**
     * A flag indicating whether or not to overwrite existing content if a conflict is found during import content operation.
     * 
     */
    @Export(name="isOverwrite", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isOverwrite;

    /**
     * @return A flag indicating whether or not to overwrite existing content if a conflict is found during import content operation.
     * 
     */
    public Output<Boolean> isOverwrite() {
        return this.isOverwrite;
    }
    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }
    /**
     * The parser names.
     * 
     */
    @Export(name="parserNames", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> parserNames;

    /**
     * @return The parser names.
     * 
     */
    public Output<List<String>> parserNames() {
        return this.parserNames;
    }
    /**
     * The source names.
     * 
     */
    @Export(name="sourceNames", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> sourceNames;

    /**
     * @return The source names.
     * 
     */
    public Output<List<String>> sourceNames() {
        return this.sourceNames;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public LogAnalyticsImportCustomContent(java.lang.String name) {
        this(name, LogAnalyticsImportCustomContentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public LogAnalyticsImportCustomContent(java.lang.String name, LogAnalyticsImportCustomContentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public LogAnalyticsImportCustomContent(java.lang.String name, LogAnalyticsImportCustomContentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private LogAnalyticsImportCustomContent(java.lang.String name, Output<java.lang.String> id, @Nullable LogAnalyticsImportCustomContentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent", name, state, makeResourceOptions(options, id), false);
    }

    private static LogAnalyticsImportCustomContentArgs makeArgs(LogAnalyticsImportCustomContentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? LogAnalyticsImportCustomContentArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static LogAnalyticsImportCustomContent get(java.lang.String name, Output<java.lang.String> id, @Nullable LogAnalyticsImportCustomContentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new LogAnalyticsImportCustomContent(name, id, state, options);
    }
}
