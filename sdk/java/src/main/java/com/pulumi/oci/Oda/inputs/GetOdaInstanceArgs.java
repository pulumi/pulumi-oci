// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetOdaInstanceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOdaInstanceArgs Empty = new GetOdaInstanceArgs();

    /**
     * Unique Digital Assistant instance identifier.
     * 
     */
    @Import(name="odaInstanceId", required=true)
    private Output<String> odaInstanceId;

    /**
     * @return Unique Digital Assistant instance identifier.
     * 
     */
    public Output<String> odaInstanceId() {
        return this.odaInstanceId;
    }

    private GetOdaInstanceArgs() {}

    private GetOdaInstanceArgs(GetOdaInstanceArgs $) {
        this.odaInstanceId = $.odaInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOdaInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOdaInstanceArgs $;

        public Builder() {
            $ = new GetOdaInstanceArgs();
        }

        public Builder(GetOdaInstanceArgs defaults) {
            $ = new GetOdaInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param odaInstanceId Unique Digital Assistant instance identifier.
         * 
         * @return builder
         * 
         */
        public Builder odaInstanceId(Output<String> odaInstanceId) {
            $.odaInstanceId = odaInstanceId;
            return this;
        }

        /**
         * @param odaInstanceId Unique Digital Assistant instance identifier.
         * 
         * @return builder
         * 
         */
        public Builder odaInstanceId(String odaInstanceId) {
            return odaInstanceId(Output.of(odaInstanceId));
        }

        public GetOdaInstanceArgs build() {
            $.odaInstanceId = Objects.requireNonNull($.odaInstanceId, "expected parameter 'odaInstanceId' to be non-null");
            return $;
        }
    }

}