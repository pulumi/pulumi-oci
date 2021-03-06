// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetScriptPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetScriptPlainArgs Empty = new GetScriptPlainArgs();

    /**
     * The APM domain ID the request is intended for.
     * 
     */
    @Import(name="apmDomainId", required=true)
    private String apmDomainId;

    /**
     * @return The APM domain ID the request is intended for.
     * 
     */
    public String apmDomainId() {
        return this.apmDomainId;
    }

    /**
     * The OCID of the script.
     * 
     */
    @Import(name="scriptId", required=true)
    private String scriptId;

    /**
     * @return The OCID of the script.
     * 
     */
    public String scriptId() {
        return this.scriptId;
    }

    private GetScriptPlainArgs() {}

    private GetScriptPlainArgs(GetScriptPlainArgs $) {
        this.apmDomainId = $.apmDomainId;
        this.scriptId = $.scriptId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetScriptPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetScriptPlainArgs $;

        public Builder() {
            $ = new GetScriptPlainArgs();
        }

        public Builder(GetScriptPlainArgs defaults) {
            $ = new GetScriptPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param apmDomainId The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param scriptId The OCID of the script.
         * 
         * @return builder
         * 
         */
        public Builder scriptId(String scriptId) {
            $.scriptId = scriptId;
            return this;
        }

        public GetScriptPlainArgs build() {
            $.apmDomainId = Objects.requireNonNull($.apmDomainId, "expected parameter 'apmDomainId' to be non-null");
            $.scriptId = Objects.requireNonNull($.scriptId, "expected parameter 'scriptId' to be non-null");
            return $;
        }
    }

}
