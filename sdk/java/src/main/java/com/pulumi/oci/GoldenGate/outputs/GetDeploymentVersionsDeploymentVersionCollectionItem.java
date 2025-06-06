// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentVersionsDeploymentVersionCollectionItem {
    /**
     * @return The type of deployment, the value determines the exact &#39;type&#39; of the service executed in the deployment. Default value is DATABASE_ORACLE.
     * 
     */
    private String deploymentType;
    /**
     * @return Indicates if OGG release contains security fix.
     * 
     */
    private Boolean isSecurityFix;
    /**
     * @return Version of OGG
     * 
     */
    private String oggVersion;
    /**
     * @return The type of release.
     * 
     */
    private String releaseType;
    /**
     * @return The time the resource was released. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    private String timeReleased;
    /**
     * @return The time until OGG version is supported. After this date has passed OGG version will not be available anymore. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    private String timeSupportedUntil;

    private GetDeploymentVersionsDeploymentVersionCollectionItem() {}
    /**
     * @return The type of deployment, the value determines the exact &#39;type&#39; of the service executed in the deployment. Default value is DATABASE_ORACLE.
     * 
     */
    public String deploymentType() {
        return this.deploymentType;
    }
    /**
     * @return Indicates if OGG release contains security fix.
     * 
     */
    public Boolean isSecurityFix() {
        return this.isSecurityFix;
    }
    /**
     * @return Version of OGG
     * 
     */
    public String oggVersion() {
        return this.oggVersion;
    }
    /**
     * @return The type of release.
     * 
     */
    public String releaseType() {
        return this.releaseType;
    }
    /**
     * @return The time the resource was released. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public String timeReleased() {
        return this.timeReleased;
    }
    /**
     * @return The time until OGG version is supported. After this date has passed OGG version will not be available anymore. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public String timeSupportedUntil() {
        return this.timeSupportedUntil;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentVersionsDeploymentVersionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deploymentType;
        private Boolean isSecurityFix;
        private String oggVersion;
        private String releaseType;
        private String timeReleased;
        private String timeSupportedUntil;
        public Builder() {}
        public Builder(GetDeploymentVersionsDeploymentVersionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deploymentType = defaults.deploymentType;
    	      this.isSecurityFix = defaults.isSecurityFix;
    	      this.oggVersion = defaults.oggVersion;
    	      this.releaseType = defaults.releaseType;
    	      this.timeReleased = defaults.timeReleased;
    	      this.timeSupportedUntil = defaults.timeSupportedUntil;
        }

        @CustomType.Setter
        public Builder deploymentType(String deploymentType) {
            if (deploymentType == null) {
              throw new MissingRequiredPropertyException("GetDeploymentVersionsDeploymentVersionCollectionItem", "deploymentType");
            }
            this.deploymentType = deploymentType;
            return this;
        }
        @CustomType.Setter
        public Builder isSecurityFix(Boolean isSecurityFix) {
            if (isSecurityFix == null) {
              throw new MissingRequiredPropertyException("GetDeploymentVersionsDeploymentVersionCollectionItem", "isSecurityFix");
            }
            this.isSecurityFix = isSecurityFix;
            return this;
        }
        @CustomType.Setter
        public Builder oggVersion(String oggVersion) {
            if (oggVersion == null) {
              throw new MissingRequiredPropertyException("GetDeploymentVersionsDeploymentVersionCollectionItem", "oggVersion");
            }
            this.oggVersion = oggVersion;
            return this;
        }
        @CustomType.Setter
        public Builder releaseType(String releaseType) {
            if (releaseType == null) {
              throw new MissingRequiredPropertyException("GetDeploymentVersionsDeploymentVersionCollectionItem", "releaseType");
            }
            this.releaseType = releaseType;
            return this;
        }
        @CustomType.Setter
        public Builder timeReleased(String timeReleased) {
            if (timeReleased == null) {
              throw new MissingRequiredPropertyException("GetDeploymentVersionsDeploymentVersionCollectionItem", "timeReleased");
            }
            this.timeReleased = timeReleased;
            return this;
        }
        @CustomType.Setter
        public Builder timeSupportedUntil(String timeSupportedUntil) {
            if (timeSupportedUntil == null) {
              throw new MissingRequiredPropertyException("GetDeploymentVersionsDeploymentVersionCollectionItem", "timeSupportedUntil");
            }
            this.timeSupportedUntil = timeSupportedUntil;
            return this;
        }
        public GetDeploymentVersionsDeploymentVersionCollectionItem build() {
            final var _resultValue = new GetDeploymentVersionsDeploymentVersionCollectionItem();
            _resultValue.deploymentType = deploymentType;
            _resultValue.isSecurityFix = isSecurityFix;
            _resultValue.oggVersion = oggVersion;
            _resultValue.releaseType = releaseType;
            _resultValue.timeReleased = timeReleased;
            _resultValue.timeSupportedUntil = timeSupportedUntil;
            return _resultValue;
        }
    }
}
