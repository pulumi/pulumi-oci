// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Secrets.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Secrets.outputs.GetSecretbundleSecretBundleContent;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSecretbundleResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Customer-provided contextual metadata for the secret.
     * 
     */
    private Map<String,String> metadata;
    /**
     * @return The contents of the secret.
     * 
     */
    private List<GetSecretbundleSecretBundleContent> secretBundleContents;
    /**
     * @return The OCID of the secret.
     * 
     */
    private String secretId;
    private @Nullable String secretVersionName;
    private @Nullable String stage;
    /**
     * @return A list of possible rotation states for the secret version.
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
     * @return The name of the secret version. Labels are unique across the different versions of a particular secret.
     * 
     */
    private String versionName;
    /**
     * @return The version number of the secret.
     * 
     */
    private String versionNumber;

    private GetSecretbundleResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Customer-provided contextual metadata for the secret.
     * 
     */
    public Map<String,String> metadata() {
        return this.metadata;
    }
    /**
     * @return The contents of the secret.
     * 
     */
    public List<GetSecretbundleSecretBundleContent> secretBundleContents() {
        return this.secretBundleContents;
    }
    /**
     * @return The OCID of the secret.
     * 
     */
    public String secretId() {
        return this.secretId;
    }
    public Optional<String> secretVersionName() {
        return Optional.ofNullable(this.secretVersionName);
    }
    public Optional<String> stage() {
        return Optional.ofNullable(this.stage);
    }
    /**
     * @return A list of possible rotation states for the secret version.
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
     * @return The name of the secret version. Labels are unique across the different versions of a particular secret.
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

    public static Builder builder(GetSecretbundleResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private Map<String,String> metadata;
        private List<GetSecretbundleSecretBundleContent> secretBundleContents;
        private String secretId;
        private @Nullable String secretVersionName;
        private @Nullable String stage;
        private List<String> stages;
        private String timeCreated;
        private String timeOfDeletion;
        private String timeOfExpiry;
        private String versionName;
        private String versionNumber;
        public Builder() {}
        public Builder(GetSecretbundleResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.metadata = defaults.metadata;
    	      this.secretBundleContents = defaults.secretBundleContents;
    	      this.secretId = defaults.secretId;
    	      this.secretVersionName = defaults.secretVersionName;
    	      this.stage = defaults.stage;
    	      this.stages = defaults.stages;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfDeletion = defaults.timeOfDeletion;
    	      this.timeOfExpiry = defaults.timeOfExpiry;
    	      this.versionName = defaults.versionName;
    	      this.versionNumber = defaults.versionNumber;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder metadata(Map<String,String> metadata) {
            if (metadata == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "metadata");
            }
            this.metadata = metadata;
            return this;
        }
        @CustomType.Setter
        public Builder secretBundleContents(List<GetSecretbundleSecretBundleContent> secretBundleContents) {
            if (secretBundleContents == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "secretBundleContents");
            }
            this.secretBundleContents = secretBundleContents;
            return this;
        }
        public Builder secretBundleContents(GetSecretbundleSecretBundleContent... secretBundleContents) {
            return secretBundleContents(List.of(secretBundleContents));
        }
        @CustomType.Setter
        public Builder secretId(String secretId) {
            if (secretId == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "secretId");
            }
            this.secretId = secretId;
            return this;
        }
        @CustomType.Setter
        public Builder secretVersionName(@Nullable String secretVersionName) {

            this.secretVersionName = secretVersionName;
            return this;
        }
        @CustomType.Setter
        public Builder stage(@Nullable String stage) {

            this.stage = stage;
            return this;
        }
        @CustomType.Setter
        public Builder stages(List<String> stages) {
            if (stages == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "stages");
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
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeOfDeletion(String timeOfDeletion) {
            if (timeOfDeletion == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "timeOfDeletion");
            }
            this.timeOfDeletion = timeOfDeletion;
            return this;
        }
        @CustomType.Setter
        public Builder timeOfExpiry(String timeOfExpiry) {
            if (timeOfExpiry == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "timeOfExpiry");
            }
            this.timeOfExpiry = timeOfExpiry;
            return this;
        }
        @CustomType.Setter
        public Builder versionName(String versionName) {
            if (versionName == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "versionName");
            }
            this.versionName = versionName;
            return this;
        }
        @CustomType.Setter
        public Builder versionNumber(String versionNumber) {
            if (versionNumber == null) {
              throw new MissingRequiredPropertyException("GetSecretbundleResult", "versionNumber");
            }
            this.versionNumber = versionNumber;
            return this;
        }
        public GetSecretbundleResult build() {
            final var _resultValue = new GetSecretbundleResult();
            _resultValue.id = id;
            _resultValue.metadata = metadata;
            _resultValue.secretBundleContents = secretBundleContents;
            _resultValue.secretId = secretId;
            _resultValue.secretVersionName = secretVersionName;
            _resultValue.stage = stage;
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
