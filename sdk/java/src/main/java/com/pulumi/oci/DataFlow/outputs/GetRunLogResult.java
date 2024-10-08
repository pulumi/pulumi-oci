// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRunLogResult {
    private @Nullable Boolean base64EncodeContent;
    /**
     * @return The content of the run log.
     * 
     */
    private String content;
    /**
     * @return The content type of the run log.
     * 
     */
    private String contentType;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String name;
    private String runId;

    private GetRunLogResult() {}
    public Optional<Boolean> base64EncodeContent() {
        return Optional.ofNullable(this.base64EncodeContent);
    }
    /**
     * @return The content of the run log.
     * 
     */
    public String content() {
        return this.content;
    }
    /**
     * @return The content type of the run log.
     * 
     */
    public String contentType() {
        return this.contentType;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String name() {
        return this.name;
    }
    public String runId() {
        return this.runId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunLogResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean base64EncodeContent;
        private String content;
        private String contentType;
        private String id;
        private String name;
        private String runId;
        public Builder() {}
        public Builder(GetRunLogResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.base64EncodeContent = defaults.base64EncodeContent;
    	      this.content = defaults.content;
    	      this.contentType = defaults.contentType;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.runId = defaults.runId;
        }

        @CustomType.Setter
        public Builder base64EncodeContent(@Nullable Boolean base64EncodeContent) {

            this.base64EncodeContent = base64EncodeContent;
            return this;
        }
        @CustomType.Setter
        public Builder content(String content) {
            if (content == null) {
              throw new MissingRequiredPropertyException("GetRunLogResult", "content");
            }
            this.content = content;
            return this;
        }
        @CustomType.Setter
        public Builder contentType(String contentType) {
            if (contentType == null) {
              throw new MissingRequiredPropertyException("GetRunLogResult", "contentType");
            }
            this.contentType = contentType;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetRunLogResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRunLogResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder runId(String runId) {
            if (runId == null) {
              throw new MissingRequiredPropertyException("GetRunLogResult", "runId");
            }
            this.runId = runId;
            return this;
        }
        public GetRunLogResult build() {
            final var _resultValue = new GetRunLogResult();
            _resultValue.base64EncodeContent = base64EncodeContent;
            _resultValue.content = content;
            _resultValue.contentType = contentType;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.runId = runId;
            return _resultValue;
        }
    }
}
