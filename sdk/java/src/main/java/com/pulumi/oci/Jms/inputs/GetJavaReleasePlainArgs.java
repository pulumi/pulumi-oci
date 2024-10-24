// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetJavaReleasePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetJavaReleasePlainArgs Empty = new GetJavaReleasePlainArgs();

    /**
     * Unique Java release version identifier
     * 
     */
    @Import(name="releaseVersion", required=true)
    private String releaseVersion;

    /**
     * @return Unique Java release version identifier
     * 
     */
    public String releaseVersion() {
        return this.releaseVersion;
    }

    private GetJavaReleasePlainArgs() {}

    private GetJavaReleasePlainArgs(GetJavaReleasePlainArgs $) {
        this.releaseVersion = $.releaseVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetJavaReleasePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetJavaReleasePlainArgs $;

        public Builder() {
            $ = new GetJavaReleasePlainArgs();
        }

        public Builder(GetJavaReleasePlainArgs defaults) {
            $ = new GetJavaReleasePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param releaseVersion Unique Java release version identifier
         * 
         * @return builder
         * 
         */
        public Builder releaseVersion(String releaseVersion) {
            $.releaseVersion = releaseVersion;
            return this;
        }

        public GetJavaReleasePlainArgs build() {
            if ($.releaseVersion == null) {
                throw new MissingRequiredPropertyException("GetJavaReleasePlainArgs", "releaseVersion");
            }
            return $;
        }
    }

}
