// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FileStorage.ExportArgs;
import com.pulumi.oci.FileStorage.inputs.ExportState;
import com.pulumi.oci.FileStorage.outputs.ExportExportOption;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Export resource in Oracle Cloud Infrastructure File Storage service.
 * 
 * Creates a new export in the specified export set, path, and
 * file system.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.FileStorage.Export;
 * import com.pulumi.oci.FileStorage.ExportArgs;
 * import com.pulumi.oci.FileStorage.inputs.ExportExportOptionArgs;
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
 *         var testExport = new Export(&#34;testExport&#34;, ExportArgs.builder()        
 *             .exportSetId(oci_file_storage_export_set.test_export_set().id())
 *             .fileSystemId(oci_file_storage_file_system.test_file_system().id())
 *             .path(var_.export_path())
 *             .exportOptions(ExportExportOptionArgs.builder()
 *                 .source(var_.export_export_options_source())
 *                 .access(var_.export_export_options_access())
 *                 .anonymousGid(var_.export_export_options_anonymous_gid())
 *                 .anonymousUid(var_.export_export_options_anonymous_uid())
 *                 .identitySquash(var_.export_export_options_identity_squash())
 *                 .requirePrivilegedSourcePort(var_.export_export_options_require_privileged_source_port())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Exports can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:FileStorage/export:Export test_export &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FileStorage/export:Export")
public class Export extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Export options for the new export. If left unspecified, defaults to:
     * 
     */
    @com.pulumi.core.annotations.Export(name="exportOptions", type=List.class, parameters={ExportExportOption.class})
    private Output<List<ExportExportOption>> exportOptions;

    /**
     * @return (Updatable) Export options for the new export. If left unspecified, defaults to:
     * 
     */
    public Output<List<ExportExportOption>> exportOptions() {
        return this.exportOptions;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
     * 
     */
    @com.pulumi.core.annotations.Export(name="exportSetId", type=String.class, parameters={})
    private Output<String> exportSetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s export set.
     * 
     */
    public Output<String> exportSetId() {
        return this.exportSetId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
     * 
     */
    @com.pulumi.core.annotations.Export(name="fileSystemId", type=String.class, parameters={})
    private Output<String> fileSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export&#39;s file system.
     * 
     */
    public Output<String> fileSystemId() {
        return this.fileSystemId;
    }
    /**
     * Path used to access the associated file system.
     * 
     */
    @com.pulumi.core.annotations.Export(name="path", type=String.class, parameters={})
    private Output<String> path;

    /**
     * @return Path used to access the associated file system.
     * 
     */
    public Output<String> path() {
        return this.path;
    }
    /**
     * The current state of this export.
     * 
     */
    @com.pulumi.core.annotations.Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of this export.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @com.pulumi.core.annotations.Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Export(String name) {
        this(name, ExportArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Export(String name, ExportArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Export(String name, ExportArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FileStorage/export:Export", name, args == null ? ExportArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Export(String name, Output<String> id, @Nullable ExportState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FileStorage/export:Export", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
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
    public static Export get(String name, Output<String> id, @Nullable ExportState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Export(name, id, state, options);
    }
}