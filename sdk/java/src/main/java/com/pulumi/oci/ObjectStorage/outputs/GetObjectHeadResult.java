// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetObjectHeadResult {
    private String archivalState;
    private String bucket;
    /**
     * @return The content-length of the object
     * 
     */
    private Integer contentLength;
    /**
     * @return The content-type of the object
     * 
     */
    private String contentType;
    /**
     * @return The etag of the object
     * 
     */
    private String etag;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The metadata of the object
     * 
     */
    private Map<String,Object> metadata;
    private String namespace;
    private String object;
    /**
     * @return The storage tier that the object is stored in.
     * * `archival-state` - Archival state of an object. This field is set only for objects in Archive tier.
     * 
     */
    private String storageTier;

    private GetObjectHeadResult() {}
    public String archivalState() {
        return this.archivalState;
    }
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The content-length of the object
     * 
     */
    public Integer contentLength() {
        return this.contentLength;
    }
    /**
     * @return The content-type of the object
     * 
     */
    public String contentType() {
        return this.contentType;
    }
    /**
     * @return The etag of the object
     * 
     */
    public String etag() {
        return this.etag;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The metadata of the object
     * 
     */
    public Map<String,Object> metadata() {
        return this.metadata;
    }
    public String namespace() {
        return this.namespace;
    }
    public String object() {
        return this.object;
    }
    /**
     * @return The storage tier that the object is stored in.
     * * `archival-state` - Archival state of an object. This field is set only for objects in Archive tier.
     * 
     */
    public String storageTier() {
        return this.storageTier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetObjectHeadResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String archivalState;
        private String bucket;
        private Integer contentLength;
        private String contentType;
        private String etag;
        private String id;
        private Map<String,Object> metadata;
        private String namespace;
        private String object;
        private String storageTier;
        public Builder() {}
        public Builder(GetObjectHeadResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archivalState = defaults.archivalState;
    	      this.bucket = defaults.bucket;
    	      this.contentLength = defaults.contentLength;
    	      this.contentType = defaults.contentType;
    	      this.etag = defaults.etag;
    	      this.id = defaults.id;
    	      this.metadata = defaults.metadata;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
    	      this.storageTier = defaults.storageTier;
        }

        @CustomType.Setter
        public Builder archivalState(String archivalState) {
            this.archivalState = Objects.requireNonNull(archivalState);
            return this;
        }
        @CustomType.Setter
        public Builder bucket(String bucket) {
            this.bucket = Objects.requireNonNull(bucket);
            return this;
        }
        @CustomType.Setter
        public Builder contentLength(Integer contentLength) {
            this.contentLength = Objects.requireNonNull(contentLength);
            return this;
        }
        @CustomType.Setter
        public Builder contentType(String contentType) {
            this.contentType = Objects.requireNonNull(contentType);
            return this;
        }
        @CustomType.Setter
        public Builder etag(String etag) {
            this.etag = Objects.requireNonNull(etag);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder metadata(Map<String,Object> metadata) {
            this.metadata = Objects.requireNonNull(metadata);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder object(String object) {
            this.object = Objects.requireNonNull(object);
            return this;
        }
        @CustomType.Setter
        public Builder storageTier(String storageTier) {
            this.storageTier = Objects.requireNonNull(storageTier);
            return this;
        }
        public GetObjectHeadResult build() {
            final var o = new GetObjectHeadResult();
            o.archivalState = archivalState;
            o.bucket = bucket;
            o.contentLength = contentLength;
            o.contentType = contentType;
            o.etag = etag;
            o.id = id;
            o.metadata = metadata;
            o.namespace = namespace;
            o.object = object;
            o.storageTier = storageTier;
            return o;
        }
    }
}