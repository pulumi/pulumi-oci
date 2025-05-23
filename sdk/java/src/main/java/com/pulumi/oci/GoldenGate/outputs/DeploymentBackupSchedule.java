// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class DeploymentBackupSchedule {
    /**
     * @return (Updatable) Name of the bucket where the object is to be uploaded in the object storage
     * 
     */
    private String bucket;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    private String compartmentId;
    /**
     * @return (Updatable) The frequency of the deployment backup schedule. Frequency can be DAILY, WEEKLY or MONTHLY.
     * 
     */
    private String frequencyBackupScheduled;
    /**
     * @return (Updatable) Parameter to allow users to create backup without trails
     * 
     */
    private Boolean isMetadataOnly;
    /**
     * @return (Updatable) Name of namespace that serves as a container for all of your buckets
     * 
     */
    private String namespace;
    /**
     * @return (Updatable) The start timestamp for the deployment backup schedule. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2024-10-25T18:19:29.600Z`.
     * 
     */
    private String timeBackupScheduled;

    private DeploymentBackupSchedule() {}
    /**
     * @return (Updatable) Name of the bucket where the object is to be uploaded in the object storage
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return (Updatable) The frequency of the deployment backup schedule. Frequency can be DAILY, WEEKLY or MONTHLY.
     * 
     */
    public String frequencyBackupScheduled() {
        return this.frequencyBackupScheduled;
    }
    /**
     * @return (Updatable) Parameter to allow users to create backup without trails
     * 
     */
    public Boolean isMetadataOnly() {
        return this.isMetadataOnly;
    }
    /**
     * @return (Updatable) Name of namespace that serves as a container for all of your buckets
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return (Updatable) The start timestamp for the deployment backup schedule. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2024-10-25T18:19:29.600Z`.
     * 
     */
    public String timeBackupScheduled() {
        return this.timeBackupScheduled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentBackupSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String compartmentId;
        private String frequencyBackupScheduled;
        private Boolean isMetadataOnly;
        private String namespace;
        private String timeBackupScheduled;
        public Builder() {}
        public Builder(DeploymentBackupSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.compartmentId = defaults.compartmentId;
    	      this.frequencyBackupScheduled = defaults.frequencyBackupScheduled;
    	      this.isMetadataOnly = defaults.isMetadataOnly;
    	      this.namespace = defaults.namespace;
    	      this.timeBackupScheduled = defaults.timeBackupScheduled;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("DeploymentBackupSchedule", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("DeploymentBackupSchedule", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder frequencyBackupScheduled(String frequencyBackupScheduled) {
            if (frequencyBackupScheduled == null) {
              throw new MissingRequiredPropertyException("DeploymentBackupSchedule", "frequencyBackupScheduled");
            }
            this.frequencyBackupScheduled = frequencyBackupScheduled;
            return this;
        }
        @CustomType.Setter
        public Builder isMetadataOnly(Boolean isMetadataOnly) {
            if (isMetadataOnly == null) {
              throw new MissingRequiredPropertyException("DeploymentBackupSchedule", "isMetadataOnly");
            }
            this.isMetadataOnly = isMetadataOnly;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("DeploymentBackupSchedule", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder timeBackupScheduled(String timeBackupScheduled) {
            if (timeBackupScheduled == null) {
              throw new MissingRequiredPropertyException("DeploymentBackupSchedule", "timeBackupScheduled");
            }
            this.timeBackupScheduled = timeBackupScheduled;
            return this;
        }
        public DeploymentBackupSchedule build() {
            final var _resultValue = new DeploymentBackupSchedule();
            _resultValue.bucket = bucket;
            _resultValue.compartmentId = compartmentId;
            _resultValue.frequencyBackupScheduled = frequencyBackupScheduled;
            _resultValue.isMetadataOnly = isMetadataOnly;
            _resultValue.namespace = namespace;
            _resultValue.timeBackupScheduled = timeBackupScheduled;
            return _resultValue;
        }
    }
}
