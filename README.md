@Filter("/**/openid-connect/**")
public class AuthenticateStsFilter implements HttpClientFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticateStsFilter.class);

    private final TokenFgtsManager tokenManager;
    private final HazelcastInstance hazelcastInstance;

    public AuthenticateStsFilter(TokenFgtsManager tokenManager, HazelcastInstance hazelcastInstance) {
        this.tokenManager = tokenManager;
        this.hazelcastInstance = hazelcastInstance;
    }

    @Override
    public Publisher<? extends HttpResponse<?>> doFilter(MutableHttpHeaders<?> request, ClientFilterChain chain) {
        IMap<String, TokenResponse> cache = hazelcastInstance.getMap("myCache");

        return Flowable.fromCallable(() -> cache.get("stsToken"))
            .switchIfEmpty(getAndUpdateToken())
            .flatMapPublisher(token -> updateAndProceedWithToken(request, chain, token));
    }

    private Single<TokenResponse> getAndUpdateToken() {
        return tokenManager.recuperaTokenStsFgts()
            .flatMap(tokenManager::updateSessionSts)
            .doOnSuccess(token -> cache.put("stsToken", token));
    }

    private Publisher<? extends HttpResponse<?>> updateAndProceedWithToken(MutableHttpHeaders<?> request, ClientFilterChain chain, TokenResponse token) {
        String authorizationHeader = String.format("Bearer %s", token.getAccess_token());
        MutableHttpHeaders headers = request.getHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", authorizationHeader);

        return chain.proceed(request);
    }

    @PostConstruct
    public void configureCache() {
        MapConfig mapConfig = hazelcastInstance.getConfig().getMapConfig("myCache");
        mapConfig.setTimeToLiveSeconds(20);
        mapConfig.setMaxIdleSeconds(20);
    }
}
