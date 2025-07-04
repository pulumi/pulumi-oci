// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSchedulerDefinitionRunBookInputParameterArgumentContent {
    /**
     * @return Bucket Name.
     * 
     */
    private String bucket;
    /**
     * @return md5 checksum of the artifact.
     * 
     */
    private String checksum;
    /**
     * @return Namespace.
     * 
     */
    private String namespace;
    /**
     * @return Object Name.
     * 
     */
    private String object;
    /**
     * @return Content Source type details.
     * 
     */
    private String sourceType;

    private GetSchedulerDefinitionRunBookInputParameterArgumentContent() {}
    /**
     * @return Bucket Name.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return md5 checksum of the artifact.
     * 
     */
    public String checksum() {
        return this.checksum;
    }
    /**
     * @return Namespace.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return Object Name.
     * 
     */
    public String object() {
        return this.object;
    }
    /**
     * @return Content Source type details.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulerDefinitionRunBookInputParameterArgumentContent defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String checksum;
        private String namespace;
        private String object;
        private String sourceType;
        public Builder() {}
        public Builder(GetSchedulerDefinitionRunBookInputParameterArgumentContent defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.checksum = defaults.checksum;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
    	      this.sourceType = defaults.sourceType;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameterArgumentContent", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder checksum(String checksum) {
            if (checksum == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameterArgumentContent", "checksum");
            }
            this.checksum = checksum;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameterArgumentContent", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder object(String object) {
            if (object == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameterArgumentContent", "object");
            }
            this.object = object;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            if (sourceType == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameterArgumentContent", "sourceType");
            }
            this.sourceType = sourceType;
            return this;
        }
        public GetSchedulerDefinitionRunBookInputParameterArgumentContent build() {
            final var _resultValue = new GetSchedulerDefinitionRunBookInputParameterArgumentContent();
            _resultValue.bucket = bucket;
            _resultValue.checksum = checksum;
            _resultValue.namespace = namespace;
            _resultValue.object = object;
            _resultValue.sourceType = sourceType;
            return _resultValue;
        }
    }
}
