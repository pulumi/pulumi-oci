// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Secrets.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecretbundleVersionsSecretBundleVersion {
    /**
     * @return The OCID of the secret.
     * 
     */
    private String secretId;
    /**
     * @return A list of possible rotation states for the secret bundle.
     * 
     */
    private List<String> stages;
    /**
     * @return The time when the secret bundle was created.
     * 
     */
    private String timeCreated;
    /**
     * @return An optional property indicating when to delete the secret version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    private String timeOfDeletion;
    /**
     * @return An optional property indicating when the secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    private String timeOfExpiry;
    /**
     * @return The version name of the secret bundle, as provided when the secret was created or last rotated.
     * 
     */
    private String versionName;
    /**
     * @return The version number of the secret.
     * 
     */
    private String versionNumber;

    private GetSecretbundleVersionsSecretBundleVersion() {}
    /**
     * @return The OCID of the secret.
     * 
     */
    public String secretId() {
        return this.secretId;
    }
    /**
     * @return A list of possible rotation states for the secret bundle.
     * 
     */
    public List<String> stages() {
        return this.stages;
    }
    /**
     * @return The time when the secret bundle was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return An optional property indicating when to delete the secret version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public String timeOfDeletion() {
        return this.timeOfDeletion;
    }
    /**
     * @return An optional property indicating when the secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public String timeOfExpiry() {
        return this.timeOfExpiry;
    }
    /**
     * @return The version name of the secret bundle, as provided when the secret was created or last rotated.
     * 
     */
    public String versionName() {
        return this.versionName;
    }
    /**
     * @return The version number of the secret.
     * 
     */
    public String versionNumber() {
        return this.versionNumber;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecretbundleVersionsSecretBundleVersion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String secretId;
        private List<String> stages;
        private String timeCreated;
        private String timeOfDeletion;
        private String timeOfExpiry;
        private String versionName;
        private String versionNumber;
        public Builder() {}
        public Builder(GetSecretbundleVersionsSecretBundleVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.secretId = defaults.secretId;
    	      this.stages = defaults.stages;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfDeletion = defaults.timeOfDeletion;
    	      this.timeOfExpiry = defaults.timeOfExpiry;
    	      this.versionName = defaults.versionName;
    	      this.versionNumber = defaults.versionNumber;
        }

        @CustomType.Setter
        public Builder secretId(String secretId) {
            if (secretId == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "secretId");
            }
            this.secretId = secretId;
            return this;
        }
        @CustomType.Setter
        public Builder stages(List<String> stages) {
            if (stages == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "stages");
            }
            this.stages = stages;
            return this;
        }
        public Builder stages(String... stages) {
            return stages(List.of(stages));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeOfDeletion(String timeOfDeletion) {
            if (timeOfDeletion == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "timeOfDeletion");
            }
            this.timeOfDeletion = timeOfDeletion;
            return this;
        }
        @CustomType.Setter
        public Builder timeOfExpiry(String timeOfExpiry) {
            if (timeOfExpiry == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "timeOfExpiry");
            }
            this.timeOfExpiry = timeOfExpiry;
            return this;
        }
        @CustomType.Setter
        public Builder versionName(String versionName) {
            if (versionName == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "versionName");
            }
            this.versionName = versionName;
            return this;
        }
        @CustomType.Setter
        public Builder versionNumber(String versionNumber) {
            if (versionNumber == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleVersionsSecretBundleVersion", "versionNumber");
            }
            this.versionNumber = versionNumber;
            return this;
        }
        public GetSecretbundleVersionsSecretBundleVersion build() {
            final var _resultValue = new GetSecretbundleVersionsSecretBundleVersion();
            _resultValue.secretId = secretId;
            _resultValue.stages = stages;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeOfDeletion = timeOfDeletion;
            _resultValue.timeOfExpiry = timeOfExpiry;
            _resultValue.versionName = versionName;
            _resultValue.versionNumber = versionNumber;
            return _resultValue;
        }
    }
}
