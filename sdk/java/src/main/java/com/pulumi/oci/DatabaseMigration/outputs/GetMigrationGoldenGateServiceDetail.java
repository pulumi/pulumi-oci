// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateServiceDetailGgsDeployment;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateServiceDetailSetting;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateServiceDetailSourceContainerDbCredential;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateServiceDetailSourceDbCredential;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationGoldenGateServiceDetailTargetDbCredential;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationGoldenGateServiceDetail {
    /**
     * @return Details about Oracle GoldenGate GGS Deployment.
     * 
     */
    private List<GetMigrationGoldenGateServiceDetailGgsDeployment> ggsDeployments;
    /**
     * @return Optional settings for Oracle GoldenGate processes
     * 
     */
    private List<GetMigrationGoldenGateServiceDetailSetting> settings;
    private List<GetMigrationGoldenGateServiceDetailSourceContainerDbCredential> sourceContainerDbCredentials;
    private List<GetMigrationGoldenGateServiceDetailSourceDbCredential> sourceDbCredentials;
    private List<GetMigrationGoldenGateServiceDetailTargetDbCredential> targetDbCredentials;

    private GetMigrationGoldenGateServiceDetail() {}
    /**
     * @return Details about Oracle GoldenGate GGS Deployment.
     * 
     */
    public List<GetMigrationGoldenGateServiceDetailGgsDeployment> ggsDeployments() {
        return this.ggsDeployments;
    }
    /**
     * @return Optional settings for Oracle GoldenGate processes
     * 
     */
    public List<GetMigrationGoldenGateServiceDetailSetting> settings() {
        return this.settings;
    }
    public List<GetMigrationGoldenGateServiceDetailSourceContainerDbCredential> sourceContainerDbCredentials() {
        return this.sourceContainerDbCredentials;
    }
    public List<GetMigrationGoldenGateServiceDetailSourceDbCredential> sourceDbCredentials() {
        return this.sourceDbCredentials;
    }
    public List<GetMigrationGoldenGateServiceDetailTargetDbCredential> targetDbCredentials() {
        return this.targetDbCredentials;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationGoldenGateServiceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMigrationGoldenGateServiceDetailGgsDeployment> ggsDeployments;
        private List<GetMigrationGoldenGateServiceDetailSetting> settings;
        private List<GetMigrationGoldenGateServiceDetailSourceContainerDbCredential> sourceContainerDbCredentials;
        private List<GetMigrationGoldenGateServiceDetailSourceDbCredential> sourceDbCredentials;
        private List<GetMigrationGoldenGateServiceDetailTargetDbCredential> targetDbCredentials;
        public Builder() {}
        public Builder(GetMigrationGoldenGateServiceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ggsDeployments = defaults.ggsDeployments;
    	      this.settings = defaults.settings;
    	      this.sourceContainerDbCredentials = defaults.sourceContainerDbCredentials;
    	      this.sourceDbCredentials = defaults.sourceDbCredentials;
    	      this.targetDbCredentials = defaults.targetDbCredentials;
        }

        @CustomType.Setter
        public Builder ggsDeployments(List<GetMigrationGoldenGateServiceDetailGgsDeployment> ggsDeployments) {
            this.ggsDeployments = Objects.requireNonNull(ggsDeployments);
            return this;
        }
        public Builder ggsDeployments(GetMigrationGoldenGateServiceDetailGgsDeployment... ggsDeployments) {
            return ggsDeployments(List.of(ggsDeployments));
        }
        @CustomType.Setter
        public Builder settings(List<GetMigrationGoldenGateServiceDetailSetting> settings) {
            this.settings = Objects.requireNonNull(settings);
            return this;
        }
        public Builder settings(GetMigrationGoldenGateServiceDetailSetting... settings) {
            return settings(List.of(settings));
        }
        @CustomType.Setter
        public Builder sourceContainerDbCredentials(List<GetMigrationGoldenGateServiceDetailSourceContainerDbCredential> sourceContainerDbCredentials) {
            this.sourceContainerDbCredentials = Objects.requireNonNull(sourceContainerDbCredentials);
            return this;
        }
        public Builder sourceContainerDbCredentials(GetMigrationGoldenGateServiceDetailSourceContainerDbCredential... sourceContainerDbCredentials) {
            return sourceContainerDbCredentials(List.of(sourceContainerDbCredentials));
        }
        @CustomType.Setter
        public Builder sourceDbCredentials(List<GetMigrationGoldenGateServiceDetailSourceDbCredential> sourceDbCredentials) {
            this.sourceDbCredentials = Objects.requireNonNull(sourceDbCredentials);
            return this;
        }
        public Builder sourceDbCredentials(GetMigrationGoldenGateServiceDetailSourceDbCredential... sourceDbCredentials) {
            return sourceDbCredentials(List.of(sourceDbCredentials));
        }
        @CustomType.Setter
        public Builder targetDbCredentials(List<GetMigrationGoldenGateServiceDetailTargetDbCredential> targetDbCredentials) {
            this.targetDbCredentials = Objects.requireNonNull(targetDbCredentials);
            return this;
        }
        public Builder targetDbCredentials(GetMigrationGoldenGateServiceDetailTargetDbCredential... targetDbCredentials) {
            return targetDbCredentials(List.of(targetDbCredentials));
        }
        public GetMigrationGoldenGateServiceDetail build() {
            final var o = new GetMigrationGoldenGateServiceDetail();
            o.ggsDeployments = ggsDeployments;
            o.settings = settings;
            o.sourceContainerDbCredentials = sourceContainerDbCredentials;
            o.sourceDbCredentials = sourceDbCredentials;
            o.targetDbCredentials = targetDbCredentials;
            return o;
        }
    }
}