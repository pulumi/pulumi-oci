// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.BigDataService.BdsInstanceOperationCertificateManagementsManagementArgs;
import com.pulumi.oci.BigDataService.inputs.BdsInstanceOperationCertificateManagementsManagementState;
import com.pulumi.oci.BigDataService.outputs.BdsInstanceOperationCertificateManagementsManagementHostCertDetail;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Bds Instance Operation Certificate Managements Management resource in Oracle Cloud Infrastructure Big Data Service service.
 * 
 * Configuring TLS/SSL for various ODH services running on the BDS cluster.
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
 * import com.pulumi.oci.BigDataService.BdsInstanceOperationCertificateManagementsManagement;
 * import com.pulumi.oci.BigDataService.BdsInstanceOperationCertificateManagementsManagementArgs;
 * import com.pulumi.oci.BigDataService.inputs.BdsInstanceOperationCertificateManagementsManagementHostCertDetailArgs;
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
 *         var testBdsInstanceOperationCertificateManagementsManagement = new BdsInstanceOperationCertificateManagementsManagement("testBdsInstanceOperationCertificateManagementsManagement", BdsInstanceOperationCertificateManagementsManagementArgs.builder()
 *             .bdsInstanceId(testBdsInstance.id())
 *             .clusterAdminPassword(bdsInstanceOperationCertificateManagementsManagementClusterAdminPassword)
 *             .services(bdsInstanceOperationCertificateManagementsManagementServices)
 *             .enableOperationCertificateManagement(enableOperationCertificateManagement)
 *             .renewOperationCertificateManagement(renewOperationCertificateManagement)
 *             .hostCertDetails(BdsInstanceOperationCertificateManagementsManagementHostCertDetailArgs.builder()
 *                 .certificate(bdsInstanceOperationCertificateManagementsManagementHostCertDetailsCertificate)
 *                 .hostName(bdsInstanceOperationCertificateManagementsManagementHostCertDetailsHostName)
 *                 .privateKey(bdsInstanceOperationCertificateManagementsManagementHostCertDetailsPrivateKey)
 *                 .build())
 *             .rootCertificate(bdsInstanceOperationCertificateManagementsManagementRootCertificate)
 *             .serverKeyPassword(bdsInstanceOperationCertificateManagementsManagementServerKeyPassword)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 */
@ResourceType(type="oci:BigDataService/bdsInstanceOperationCertificateManagementsManagement:BdsInstanceOperationCertificateManagementsManagement")
public class BdsInstanceOperationCertificateManagementsManagement extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the cluster.
     * 
     */
    @Export(name="bdsInstanceId", refs={String.class}, tree="[0]")
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }
    /**
     * Base-64 encoded password for the cluster admin user.
     * 
     */
    @Export(name="clusterAdminPassword", refs={String.class}, tree="[0]")
    private Output<String> clusterAdminPassword;

    /**
     * @return Base-64 encoded password for the cluster admin user.
     * 
     */
    public Output<String> clusterAdminPassword() {
        return this.clusterAdminPassword;
    }
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     */
    @Export(name="enableOperationCertificateManagement", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> enableOperationCertificateManagement;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     */
    public Output<Boolean> enableOperationCertificateManagement() {
        return this.enableOperationCertificateManagement;
    }
    /**
     * List of leaf certificates to use for services on each host. If custom host certificate is provided the root certificate becomes required.
     * 
     */
    @Export(name="hostCertDetails", refs={List.class,BdsInstanceOperationCertificateManagementsManagementHostCertDetail.class}, tree="[0,1]")
    private Output<List<BdsInstanceOperationCertificateManagementsManagementHostCertDetail>> hostCertDetails;

    /**
     * @return List of leaf certificates to use for services on each host. If custom host certificate is provided the root certificate becomes required.
     * 
     */
    public Output<List<BdsInstanceOperationCertificateManagementsManagementHostCertDetail>> hostCertDetails() {
        return this.hostCertDetails;
    }
    /**
     * (Updatable) A required field when set to `true` calls renew action and when set to `false` defaults to enable_operation_certificate_management&#39;s value action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="renewOperationCertificateManagement", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> renewOperationCertificateManagement;

    /**
     * @return (Updatable) A required field when set to `true` calls renew action and when set to `false` defaults to enable_operation_certificate_management&#39;s value action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> renewOperationCertificateManagement() {
        return this.renewOperationCertificateManagement;
    }
    /**
     * Plain text certificate/s in order, separated by new line character. If not provided in request a self-signed root certificate is generated inside the cluster. In case hostCertDetails is provided, root certificate is mandatory.
     * 
     */
    @Export(name="rootCertificate", refs={String.class}, tree="[0]")
    private Output<String> rootCertificate;

    /**
     * @return Plain text certificate/s in order, separated by new line character. If not provided in request a self-signed root certificate is generated inside the cluster. In case hostCertDetails is provided, root certificate is mandatory.
     * 
     */
    public Output<String> rootCertificate() {
        return this.rootCertificate;
    }
    /**
     * Base-64 encoded password for CA certificate&#39;s private key. This value can be empty.
     * 
     */
    @Export(name="serverKeyPassword", refs={String.class}, tree="[0]")
    private Output<String> serverKeyPassword;

    /**
     * @return Base-64 encoded password for CA certificate&#39;s private key. This value can be empty.
     * 
     */
    public Output<String> serverKeyPassword() {
        return this.serverKeyPassword;
    }
    /**
     * List of services for which certificate needs to be enabled.
     * 
     */
    @Export(name="services", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> services;

    /**
     * @return List of services for which certificate needs to be enabled.
     * 
     */
    public Output<List<String>> services() {
        return this.services;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public BdsInstanceOperationCertificateManagementsManagement(java.lang.String name) {
        this(name, BdsInstanceOperationCertificateManagementsManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public BdsInstanceOperationCertificateManagementsManagement(java.lang.String name, BdsInstanceOperationCertificateManagementsManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public BdsInstanceOperationCertificateManagementsManagement(java.lang.String name, BdsInstanceOperationCertificateManagementsManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceOperationCertificateManagementsManagement:BdsInstanceOperationCertificateManagementsManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private BdsInstanceOperationCertificateManagementsManagement(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceOperationCertificateManagementsManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceOperationCertificateManagementsManagement:BdsInstanceOperationCertificateManagementsManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static BdsInstanceOperationCertificateManagementsManagementArgs makeArgs(BdsInstanceOperationCertificateManagementsManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? BdsInstanceOperationCertificateManagementsManagementArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "clusterAdminPassword",
                "serverKeyPassword"
            ))
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
    public static BdsInstanceOperationCertificateManagementsManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceOperationCertificateManagementsManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new BdsInstanceOperationCertificateManagementsManagement(name, id, state, options);
    }
}
