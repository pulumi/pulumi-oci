// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetKeysKeyRestoreFromFile {
    private final String contentLength;
    private final String contentMd5;
    private final String restoreKeyFromFileDetails;

    @CustomType.Constructor
    private GetKeysKeyRestoreFromFile(
        @CustomType.Parameter("contentLength") String contentLength,
        @CustomType.Parameter("contentMd5") String contentMd5,
        @CustomType.Parameter("restoreKeyFromFileDetails") String restoreKeyFromFileDetails) {
        this.contentLength = contentLength;
        this.contentMd5 = contentMd5;
        this.restoreKeyFromFileDetails = restoreKeyFromFileDetails;
    }

    public String contentLength() {
        return this.contentLength;
    }
    public String contentMd5() {
        return this.contentMd5;
    }
    public String restoreKeyFromFileDetails() {
        return this.restoreKeyFromFileDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeysKeyRestoreFromFile defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String contentLength;
        private String contentMd5;
        private String restoreKeyFromFileDetails;

        public Builder() {
    	      // Empty
        }

        public Builder(GetKeysKeyRestoreFromFile defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.contentLength = defaults.contentLength;
    	      this.contentMd5 = defaults.contentMd5;
    	      this.restoreKeyFromFileDetails = defaults.restoreKeyFromFileDetails;
        }

        public Builder contentLength(String contentLength) {
            this.contentLength = Objects.requireNonNull(contentLength);
            return this;
        }
        public Builder contentMd5(String contentMd5) {
            this.contentMd5 = Objects.requireNonNull(contentMd5);
            return this;
        }
        public Builder restoreKeyFromFileDetails(String restoreKeyFromFileDetails) {
            this.restoreKeyFromFileDetails = Objects.requireNonNull(restoreKeyFromFileDetails);
            return this;
        }        public GetKeysKeyRestoreFromFile build() {
            return new GetKeysKeyRestoreFromFile(contentLength, contentMd5, restoreKeyFromFileDetails);
        }
    }
}
