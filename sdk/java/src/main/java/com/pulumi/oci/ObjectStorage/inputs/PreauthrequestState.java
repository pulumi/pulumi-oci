// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PreauthrequestState extends com.pulumi.resources.ResourceArgs {

    public static final PreauthrequestState Empty = new PreauthrequestState();

    /**
     * The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
     * 
     */
    @Import(name="accessType")
    private @Nullable Output<String> accessType;

    /**
     * @return The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
     * 
     */
    public Optional<Output<String>> accessType() {
        return Optional.ofNullable(this.accessType);
    }

    /**
     * The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
     * 
     */
    @Import(name="accessUri")
    private @Nullable Output<String> accessUri;

    /**
     * @return The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
     * 
     */
    public Optional<Output<String>> accessUri() {
        return Optional.ofNullable(this.accessUri);
    }

    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * Specifies whether a list operation is allowed on a PAR with accessType &#34;AnyObjectRead&#34; or &#34;AnyObjectReadWrite&#34;. Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
     * 
     */
    @Import(name="bucketListingAction")
    private @Nullable Output<String> bucketListingAction;

    /**
     * @return Specifies whether a list operation is allowed on a PAR with accessType &#34;AnyObjectRead&#34; or &#34;AnyObjectReadWrite&#34;. Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
     * 
     */
    public Optional<Output<String>> bucketListingAction() {
        return Optional.ofNullable(this.bucketListingAction);
    }

    /**
     * A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The Object Storage namespace used for the request.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Object Storage namespace used for the request.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
     * 
     * @deprecated
     * The &#39;object&#39; field has been deprecated. Please use &#39;object_name&#39; instead.
     * 
     */
    @Deprecated /* The 'object' field has been deprecated. Please use 'object_name' instead. */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
     * 
     * @deprecated
     * The &#39;object&#39; field has been deprecated. Please use &#39;object_name&#39; instead.
     * 
     */
    @Deprecated /* The 'object' field has been deprecated. Please use 'object_name' instead. */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    /**
     * The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
     * 
     */
    @Import(name="objectName")
    private @Nullable Output<String> objectName;

    /**
     * @return The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
     * 
     */
    public Optional<Output<String>> objectName() {
        return Optional.ofNullable(this.objectName);
    }

    /**
     * The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
     * 
     */
    @Import(name="parId")
    private @Nullable Output<String> parId;

    /**
     * @return The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
     * 
     */
    public Optional<Output<String>> parId() {
        return Optional.ofNullable(this.parId);
    }

    /**
     * The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
     * 
     */
    @Import(name="timeExpires")
    private @Nullable Output<String> timeExpires;

    /**
     * @return The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
     * 
     */
    public Optional<Output<String>> timeExpires() {
        return Optional.ofNullable(this.timeExpires);
    }

    private PreauthrequestState() {}

    private PreauthrequestState(PreauthrequestState $) {
        this.accessType = $.accessType;
        this.accessUri = $.accessUri;
        this.bucket = $.bucket;
        this.bucketListingAction = $.bucketListingAction;
        this.name = $.name;
        this.namespace = $.namespace;
        this.object = $.object;
        this.objectName = $.objectName;
        this.parId = $.parId;
        this.timeCreated = $.timeCreated;
        this.timeExpires = $.timeExpires;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PreauthrequestState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PreauthrequestState $;

        public Builder() {
            $ = new PreauthrequestState();
        }

        public Builder(PreauthrequestState defaults) {
            $ = new PreauthrequestState(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessType The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
         * 
         * @return builder
         * 
         */
        public Builder accessType(@Nullable Output<String> accessType) {
            $.accessType = accessType;
            return this;
        }

        /**
         * @param accessType The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
         * 
         * @return builder
         * 
         */
        public Builder accessType(String accessType) {
            return accessType(Output.of(accessType));
        }

        /**
         * @param accessUri The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
         * 
         * @return builder
         * 
         */
        public Builder accessUri(@Nullable Output<String> accessUri) {
            $.accessUri = accessUri;
            return this;
        }

        /**
         * @param accessUri The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
         * 
         * @return builder
         * 
         */
        public Builder accessUri(String accessUri) {
            return accessUri(Output.of(accessUri));
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param bucketListingAction Specifies whether a list operation is allowed on a PAR with accessType &#34;AnyObjectRead&#34; or &#34;AnyObjectReadWrite&#34;. Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
         * 
         * @return builder
         * 
         */
        public Builder bucketListingAction(@Nullable Output<String> bucketListingAction) {
            $.bucketListingAction = bucketListingAction;
            return this;
        }

        /**
         * @param bucketListingAction Specifies whether a list operation is allowed on a PAR with accessType &#34;AnyObjectRead&#34; or &#34;AnyObjectReadWrite&#34;. Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
         * 
         * @return builder
         * 
         */
        public Builder bucketListingAction(String bucketListingAction) {
            return bucketListingAction(Output.of(bucketListingAction));
        }

        /**
         * @param name A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;object&#39; field has been deprecated. Please use &#39;object_name&#39; instead.
         * 
         */
        @Deprecated /* The 'object' field has been deprecated. Please use 'object_name' instead. */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;object&#39; field has been deprecated. Please use &#39;object_name&#39; instead.
         * 
         */
        @Deprecated /* The 'object' field has been deprecated. Please use 'object_name' instead. */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param objectName The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
         * 
         * @return builder
         * 
         */
        public Builder objectName(@Nullable Output<String> objectName) {
            $.objectName = objectName;
            return this;
        }

        /**
         * @param objectName The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
         * 
         * @return builder
         * 
         */
        public Builder objectName(String objectName) {
            return objectName(Output.of(objectName));
        }

        /**
         * @param parId The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
         * 
         * @return builder
         * 
         */
        public Builder parId(@Nullable Output<String> parId) {
            $.parId = parId;
            return this;
        }

        /**
         * @param parId The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
         * 
         * @return builder
         * 
         */
        public Builder parId(String parId) {
            return parId(Output.of(parId));
        }

        /**
         * @param timeCreated The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeExpires The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(@Nullable Output<String> timeExpires) {
            $.timeExpires = timeExpires;
            return this;
        }

        /**
         * @param timeExpires The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(String timeExpires) {
            return timeExpires(Output.of(timeExpires));
        }

        public PreauthrequestState build() {
            return $;
        }
    }

}