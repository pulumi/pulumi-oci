// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetJavaFamilyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetJavaFamilyPlainArgs Empty = new GetJavaFamilyPlainArgs();

    /**
     * Unique Java family version identifier.
     * 
     */
    @Import(name="familyVersion", required=true)
    private String familyVersion;

    /**
     * @return Unique Java family version identifier.
     * 
     */
    public String familyVersion() {
        return this.familyVersion;
    }

    private GetJavaFamilyPlainArgs() {}

    private GetJavaFamilyPlainArgs(GetJavaFamilyPlainArgs $) {
        this.familyVersion = $.familyVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetJavaFamilyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetJavaFamilyPlainArgs $;

        public Builder() {
            $ = new GetJavaFamilyPlainArgs();
        }

        public Builder(GetJavaFamilyPlainArgs defaults) {
            $ = new GetJavaFamilyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param familyVersion Unique Java family version identifier.
         * 
         * @return builder
         * 
         */
        public Builder familyVersion(String familyVersion) {
            $.familyVersion = familyVersion;
            return this;
        }

        public GetJavaFamilyPlainArgs build() {
            $.familyVersion = Objects.requireNonNull($.familyVersion, "expected parameter 'familyVersion' to be non-null");
            return $;
        }
    }

}