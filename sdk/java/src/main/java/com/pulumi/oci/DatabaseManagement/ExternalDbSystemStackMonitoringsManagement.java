// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalDbSystemStackMonitoringsManagementArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemStackMonitoringsManagementState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the External Db System Stack Monitorings Management resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Enables Stack Monitoring for all the components of the specified
 * external DB system (except databases).
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
 * import com.pulumi.oci.DatabaseManagement.ExternalDbSystemStackMonitoringsManagement;
 * import com.pulumi.oci.DatabaseManagement.ExternalDbSystemStackMonitoringsManagementArgs;
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
 *         var testExternalDbSystemStackMonitoringsManagement = new ExternalDbSystemStackMonitoringsManagement("testExternalDbSystemStackMonitoringsManagement", ExternalDbSystemStackMonitoringsManagementArgs.builder()
 *             .externalDbSystemId(testExternalDbSystem.id())
 *             .enableStackMonitoring(enableStackMonitoring)
 *             .isEnabled(externalDbSystemStackMonitoringsManagementIsEnabled)
 *             .metadata(externalDbSystemStackMonitoringsManagementMetadata)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalDbSystemStackMonitoringsManagement:ExternalDbSystemStackMonitoringsManagement")
public class ExternalDbSystemStackMonitoringsManagement extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="enableStackMonitoring", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> enableStackMonitoring;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enableStackMonitoring() {
        return this.enableStackMonitoring;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    @Export(name="externalDbSystemId", refs={String.class}, tree="[0]")
    private Output<String> externalDbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    public Output<String> externalDbSystemId() {
        return this.externalDbSystemId;
    }
    /**
     * The status of the associated service.
     * 
     */
    @Export(name="isEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isEnabled;

    /**
     * @return The status of the associated service.
     * 
     */
    public Output<Boolean> isEnabled() {
        return this.isEnabled;
    }
    /**
     * The associated service-specific inputs in JSON string format, which Database Management can identify.
     * 
     */
    @Export(name="metadata", refs={String.class}, tree="[0]")
    private Output<String> metadata;

    /**
     * @return The associated service-specific inputs in JSON string format, which Database Management can identify.
     * 
     */
    public Output<String> metadata() {
        return this.metadata;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalDbSystemStackMonitoringsManagement(java.lang.String name) {
        this(name, ExternalDbSystemStackMonitoringsManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalDbSystemStackMonitoringsManagement(java.lang.String name, ExternalDbSystemStackMonitoringsManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalDbSystemStackMonitoringsManagement(java.lang.String name, ExternalDbSystemStackMonitoringsManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalDbSystemStackMonitoringsManagement:ExternalDbSystemStackMonitoringsManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExternalDbSystemStackMonitoringsManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalDbSystemStackMonitoringsManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalDbSystemStackMonitoringsManagement:ExternalDbSystemStackMonitoringsManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ExternalDbSystemStackMonitoringsManagementArgs makeArgs(ExternalDbSystemStackMonitoringsManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExternalDbSystemStackMonitoringsManagementArgs.Empty : args;
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
    public static ExternalDbSystemStackMonitoringsManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalDbSystemStackMonitoringsManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalDbSystemStackMonitoringsManagement(name, id, state, options);
    }
}
