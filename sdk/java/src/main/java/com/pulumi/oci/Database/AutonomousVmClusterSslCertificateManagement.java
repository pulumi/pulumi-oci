// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.AutonomousVmClusterSslCertificateManagementArgs;
import com.pulumi.oci.Database.inputs.AutonomousVmClusterSslCertificateManagementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Autonomous Vm Cluster Ssl Certificate Management resource in Oracle Cloud Infrastructure Database service.
 * 
 * Rotates the SSL certificates for Autonomous Exadata VM cluster.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Database.AutonomousVmClusterSslCertificateManagement;
 * import com.pulumi.oci.Database.AutonomousVmClusterSslCertificateManagementArgs;
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
 *         var testAutonomousVmClusterSslCertificateManagement = new AutonomousVmClusterSslCertificateManagement(&#34;testAutonomousVmClusterSslCertificateManagement&#34;, AutonomousVmClusterSslCertificateManagementArgs.builder()        
 *             .autonomousVmClusterId(oci_database_autonomous_vm_cluster.test_autonomous_vm_cluster().id())
 *             .certificateGenerationType(var_.autonomous_vm_cluster_ssl_certificate_management_certificate_generation_type())
 *             .caBundleId(oci_certificates_management_ca_bundle.test_ca_bundle().id())
 *             .certificateAuthorityId(oci_certificates_management_certificate_authority.test_certificate_authority().id())
 *             .certificateId(oci_apigateway_certificate.test_certificate().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Import is not supported for this resource.
 * 
 */
@ResourceType(type="oci:Database/autonomousVmClusterSslCertificateManagement:AutonomousVmClusterSslCertificateManagement")
public class AutonomousVmClusterSslCertificateManagement extends com.pulumi.resources.CustomResource {
    /**
     * The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="autonomousVmClusterId", type=String.class, parameters={})
    private Output<String> autonomousVmClusterId;

    /**
     * @return The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> autonomousVmClusterId() {
        return this.autonomousVmClusterId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate bundle.
     * 
     */
    @Export(name="caBundleId", type=String.class, parameters={})
    private Output<String> caBundleId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate bundle.
     * 
     */
    public Output<String> caBundleId() {
        return this.caBundleId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate authority.
     * 
     */
    @Export(name="certificateAuthorityId", type=String.class, parameters={})
    private Output<String> certificateAuthorityId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate authority.
     * 
     */
    public Output<String> certificateAuthorityId() {
        return this.certificateAuthorityId;
    }
    /**
     * Specify SYSTEM for using Oracle managed certificates. Specify BYOC when you want to bring your own certificate.
     * 
     */
    @Export(name="certificateGenerationType", type=String.class, parameters={})
    private Output<String> certificateGenerationType;

    /**
     * @return Specify SYSTEM for using Oracle managed certificates. Specify BYOC when you want to bring your own certificate.
     * 
     */
    public Output<String> certificateGenerationType() {
        return this.certificateGenerationType;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate to use.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="certificateId", type=String.class, parameters={})
    private Output<String> certificateId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate to use.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> certificateId() {
        return this.certificateId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AutonomousVmClusterSslCertificateManagement(String name) {
        this(name, AutonomousVmClusterSslCertificateManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AutonomousVmClusterSslCertificateManagement(String name, AutonomousVmClusterSslCertificateManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AutonomousVmClusterSslCertificateManagement(String name, AutonomousVmClusterSslCertificateManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/autonomousVmClusterSslCertificateManagement:AutonomousVmClusterSslCertificateManagement", name, args == null ? AutonomousVmClusterSslCertificateManagementArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private AutonomousVmClusterSslCertificateManagement(String name, Output<String> id, @Nullable AutonomousVmClusterSslCertificateManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/autonomousVmClusterSslCertificateManagement:AutonomousVmClusterSslCertificateManagement", name, state, makeResourceOptions(options, id));
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
    public static AutonomousVmClusterSslCertificateManagement get(String name, Output<String> id, @Nullable AutonomousVmClusterSslCertificateManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AutonomousVmClusterSslCertificateManagement(name, id, state, options);
    }
}