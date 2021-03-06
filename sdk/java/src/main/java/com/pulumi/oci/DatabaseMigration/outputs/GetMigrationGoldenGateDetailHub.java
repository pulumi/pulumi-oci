// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateDetailHubRestAdminCredential;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateDetailHubSourceDbAdminCredential;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateDetailHubTargetDbAdminCredential;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationGoldenGateDetailHub {
    /**
     * @return OCID of GoldenGate compute instance.
     * 
     */
    private final String computeId;
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    private final List<GetMigrationGoldenGateDetailHubRestAdminCredential> restAdminCredentials;
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    private final List<GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential> sourceContainerDbAdminCredentials;
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    private final List<GetMigrationGoldenGateDetailHubSourceDbAdminCredential> sourceDbAdminCredentials;
    /**
     * @return Name of GoldenGate deployment to operate on source database
     * 
     */
    private final String sourceMicroservicesDeploymentName;
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    private final List<GetMigrationGoldenGateDetailHubTargetDbAdminCredential> targetDbAdminCredentials;
    /**
     * @return Name of GoldenGate deployment to operate on target database
     * 
     */
    private final String targetMicroservicesDeploymentName;
    /**
     * @return Oracle GoldenGate hub&#39;s REST endpoint. Refer to https://docs.oracle.com/en/middleware/goldengate/core/19.1/securing/network.html#GUID-A709DA55-111D-455E-8942-C9BDD1E38CAA
     * 
     */
    private final String url;

    @CustomType.Constructor
    private GetMigrationGoldenGateDetailHub(
        @CustomType.Parameter("computeId") String computeId,
        @CustomType.Parameter("restAdminCredentials") List<GetMigrationGoldenGateDetailHubRestAdminCredential> restAdminCredentials,
        @CustomType.Parameter("sourceContainerDbAdminCredentials") List<GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential> sourceContainerDbAdminCredentials,
        @CustomType.Parameter("sourceDbAdminCredentials") List<GetMigrationGoldenGateDetailHubSourceDbAdminCredential> sourceDbAdminCredentials,
        @CustomType.Parameter("sourceMicroservicesDeploymentName") String sourceMicroservicesDeploymentName,
        @CustomType.Parameter("targetDbAdminCredentials") List<GetMigrationGoldenGateDetailHubTargetDbAdminCredential> targetDbAdminCredentials,
        @CustomType.Parameter("targetMicroservicesDeploymentName") String targetMicroservicesDeploymentName,
        @CustomType.Parameter("url") String url) {
        this.computeId = computeId;
        this.restAdminCredentials = restAdminCredentials;
        this.sourceContainerDbAdminCredentials = sourceContainerDbAdminCredentials;
        this.sourceDbAdminCredentials = sourceDbAdminCredentials;
        this.sourceMicroservicesDeploymentName = sourceMicroservicesDeploymentName;
        this.targetDbAdminCredentials = targetDbAdminCredentials;
        this.targetMicroservicesDeploymentName = targetMicroservicesDeploymentName;
        this.url = url;
    }

    /**
     * @return OCID of GoldenGate compute instance.
     * 
     */
    public String computeId() {
        return this.computeId;
    }
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    public List<GetMigrationGoldenGateDetailHubRestAdminCredential> restAdminCredentials() {
        return this.restAdminCredentials;
    }
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    public List<GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential> sourceContainerDbAdminCredentials() {
        return this.sourceContainerDbAdminCredentials;
    }
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    public List<GetMigrationGoldenGateDetailHubSourceDbAdminCredential> sourceDbAdminCredentials() {
        return this.sourceDbAdminCredentials;
    }
    /**
     * @return Name of GoldenGate deployment to operate on source database
     * 
     */
    public String sourceMicroservicesDeploymentName() {
        return this.sourceMicroservicesDeploymentName;
    }
    /**
     * @return Database Administrator Credentials details.
     * 
     */
    public List<GetMigrationGoldenGateDetailHubTargetDbAdminCredential> targetDbAdminCredentials() {
        return this.targetDbAdminCredentials;
    }
    /**
     * @return Name of GoldenGate deployment to operate on target database
     * 
     */
    public String targetMicroservicesDeploymentName() {
        return this.targetMicroservicesDeploymentName;
    }
    /**
     * @return Oracle GoldenGate hub&#39;s REST endpoint. Refer to https://docs.oracle.com/en/middleware/goldengate/core/19.1/securing/network.html#GUID-A709DA55-111D-455E-8942-C9BDD1E38CAA
     * 
     */
    public String url() {
        return this.url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationGoldenGateDetailHub defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String computeId;
        private List<GetMigrationGoldenGateDetailHubRestAdminCredential> restAdminCredentials;
        private List<GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential> sourceContainerDbAdminCredentials;
        private List<GetMigrationGoldenGateDetailHubSourceDbAdminCredential> sourceDbAdminCredentials;
        private String sourceMicroservicesDeploymentName;
        private List<GetMigrationGoldenGateDetailHubTargetDbAdminCredential> targetDbAdminCredentials;
        private String targetMicroservicesDeploymentName;
        private String url;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationGoldenGateDetailHub defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.computeId = defaults.computeId;
    	      this.restAdminCredentials = defaults.restAdminCredentials;
    	      this.sourceContainerDbAdminCredentials = defaults.sourceContainerDbAdminCredentials;
    	      this.sourceDbAdminCredentials = defaults.sourceDbAdminCredentials;
    	      this.sourceMicroservicesDeploymentName = defaults.sourceMicroservicesDeploymentName;
    	      this.targetDbAdminCredentials = defaults.targetDbAdminCredentials;
    	      this.targetMicroservicesDeploymentName = defaults.targetMicroservicesDeploymentName;
    	      this.url = defaults.url;
        }

        public Builder computeId(String computeId) {
            this.computeId = Objects.requireNonNull(computeId);
            return this;
        }
        public Builder restAdminCredentials(List<GetMigrationGoldenGateDetailHubRestAdminCredential> restAdminCredentials) {
            this.restAdminCredentials = Objects.requireNonNull(restAdminCredentials);
            return this;
        }
        public Builder restAdminCredentials(GetMigrationGoldenGateDetailHubRestAdminCredential... restAdminCredentials) {
            return restAdminCredentials(List.of(restAdminCredentials));
        }
        public Builder sourceContainerDbAdminCredentials(List<GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential> sourceContainerDbAdminCredentials) {
            this.sourceContainerDbAdminCredentials = Objects.requireNonNull(sourceContainerDbAdminCredentials);
            return this;
        }
        public Builder sourceContainerDbAdminCredentials(GetMigrationGoldenGateDetailHubSourceContainerDbAdminCredential... sourceContainerDbAdminCredentials) {
            return sourceContainerDbAdminCredentials(List.of(sourceContainerDbAdminCredentials));
        }
        public Builder sourceDbAdminCredentials(List<GetMigrationGoldenGateDetailHubSourceDbAdminCredential> sourceDbAdminCredentials) {
            this.sourceDbAdminCredentials = Objects.requireNonNull(sourceDbAdminCredentials);
            return this;
        }
        public Builder sourceDbAdminCredentials(GetMigrationGoldenGateDetailHubSourceDbAdminCredential... sourceDbAdminCredentials) {
            return sourceDbAdminCredentials(List.of(sourceDbAdminCredentials));
        }
        public Builder sourceMicroservicesDeploymentName(String sourceMicroservicesDeploymentName) {
            this.sourceMicroservicesDeploymentName = Objects.requireNonNull(sourceMicroservicesDeploymentName);
            return this;
        }
        public Builder targetDbAdminCredentials(List<GetMigrationGoldenGateDetailHubTargetDbAdminCredential> targetDbAdminCredentials) {
            this.targetDbAdminCredentials = Objects.requireNonNull(targetDbAdminCredentials);
            return this;
        }
        public Builder targetDbAdminCredentials(GetMigrationGoldenGateDetailHubTargetDbAdminCredential... targetDbAdminCredentials) {
            return targetDbAdminCredentials(List.of(targetDbAdminCredentials));
        }
        public Builder targetMicroservicesDeploymentName(String targetMicroservicesDeploymentName) {
            this.targetMicroservicesDeploymentName = Objects.requireNonNull(targetMicroservicesDeploymentName);
            return this;
        }
        public Builder url(String url) {
            this.url = Objects.requireNonNull(url);
            return this;
        }        public GetMigrationGoldenGateDetailHub build() {
            return new GetMigrationGoldenGateDetailHub(computeId, restAdminCredentials, sourceContainerDbAdminCredentials, sourceDbAdminCredentials, sourceMicroservicesDeploymentName, targetDbAdminCredentials, targetMicroservicesDeploymentName, url);
        }
    }
}
