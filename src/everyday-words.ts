/**
 * Words that ordinary security prose uses in their everyday sense and that are also package names
 * ("send a crafted request", "buffer overflow", "session cookie", "the next release"). A package
 * with one of these names is matched in a news story only when the story is about packages or
 * names a release of it; see `packageMentioned` in matching.ts.
 *
 * A name that is not listed here ("axios", "django", "rails", "webpack") is treated as the name of
 * the software wherever it appears. Add a word when it produces unrelated matches; the list trades
 * a little recall for names that are also common words, and nothing for any other name.
 */
const WORDS = `
able about above accept accepts access account accounts across action actions active activity actor
actors actual add added address addresses admin advisory affect affected after again against agent
agents alert alerts alias all allow allowed allows almost alone along already also always among amount
analysis and another answer any anyone anything app appear application applications apply approach
archive area argument arguments around array arrive article ask assert asset assets attach attack
attacker attackers attacks attempt attribute attributes audit auth author auto available avoid away
back backup bad banner base based basic batch because become been before begin behavior being below
best better between big binary bind bit bits black blank block blocks blue board body boolean boot
both bottom bound box branch break bridge brief bring broken browser buffer buffers bug bugs build
builder built bundle bus business but button bypass byte bytes cache call callback called caller calls
can cannot capture card care case cases cast catch cause caused causes center central certain chain
chains chalk chance change changes channel channels char character characters chart check checks child
children choice choose chunk circle class classes clean clear click client clients clock clone close
closed cloud cluster code codes collect collection color colors column columns combine come command
commands comment comments commit common community company compare compile complete component
components compress compute concat concern condition config configuration configure confirm connect
connection connections console constant constants contact contain container contains content contents
context continue control controls convert cookie cookies copy core correct cost could count counter
country course cover crash crawl create created credential credentials critical cross crypto
cryptography current cursor custom customer customers cut cycle daily damage dark dash data database
date dates day days dead deal debug decode deep default defaults define defined delay delete deliver
delivery demand demo deny depend depends deploy depth describe design desktop destroy detail details
detect develop developer developers device devices dialog diff different digest direct directory
disable discover disk dispatch display distance does doing domain domains done door double down
download draft draw drive driver drop due dump during each early easy echo edge edit editor effect
either element elements else email embed emit empty enable encode encoding end endpoint endpoints
engine enough ensure enter entire entity entry enum env environment equal equals error errors escape
even event events ever every everyone everything exact example except exception exchange exec execute
execution exist exists exit expand expect explain exploit exploits export expose exposed extend
extension extensions extra extract face fact fail failed fails failure fall false family far fast
fault feature features feed feedback fetch few field fields figure file files fill filter filters final
find finding fire firewall first fit five fix fixed fixes flag flags flash flat flaw flaws flex flight
float flood floor flow flush focus folder follow font food foo force foreign forget fork form format
forms forward found four frame framework free fresh friend from front full function functions future
gain game gate gateway general generate generic get gets give given glob global goal goes going gone
good got grant graph gray great green grid ground group groups grow guard guess guest guide hack half
hand handle handler handlers hang happen hard hardware has hash have head header headers health heap
hear heart heavy held help helper here hidden hide high history hit hold hole home hook hooks host
hosts hot hour hours house how however html http https hub huge human hundred icon idea identity idle
ignore image images impact implement import important improve include includes index info inform
information inherit inherits init initial inject injection inline inner input inputs insert inside
inspect install installed instance instead integer intent interface internal internet into invalid
invoke issue issues item items its itself job jobs join jump just keep kernel key keys kill kind know
known label labels lack language large last late later latest launch layer layout lazy lead leak leaks
learn least leave left legacy length less let letter level levels library license life light like
limit limits line lines link links list listen lists little live load loader local locale location
lock locks log logger logging logic login logs long look lookup loop loose lose loss lost lot low lower
machine made magic mail main maintain major make maker makes malicious malware manage manager manual
many map mapping maps mark marked market mask master match matches material matter may mean means
measure media meet member members memory menu merge message messages meta method methods metric
metrics middle might mime mind minimum minor minute minutes mirror miss missing mix mobile mock mode
model models modern modify module modules moment money monitor month months more most mount mouse move
much multi multiple must name named names native nature near need needs negative nest net network
networks never new news next nice night node nodes noise none normal not note notes nothing notice
notify now null number numbers object objects observe obtain occur off offer office offset often old
once one online only open opened opens operation operations operator option optional options order
origin original other others our out outer output outputs over overflow override own owner pack
package packages packet packets pad page pages paint pair panel paper param parameter parameters params
parent parse parser part parts party pass passed password passwords past patch patched patches path
paths pattern patterns pause pay payload payment peak peer pending people per perform period permit
person phase phone photo pick picture piece ping pipe pipeline pixel place plain plan platform play
player please plugin plugins point pointer points policy poll pool pop popular port ports position
positive possible post power prefer prefix prepare present press pretty prevent preview previous price
primary print printer prior priority privacy private privilege privileges probe problem proceed
process processes produce product products profile program progress project projects promise prompt
proof proper properties property protect protocol prove provide provider proxy public publish pull
pump purge purpose push put quality query question queue quick quiet quite quote race radio raise
random range rank rate rather raw reach read reader reading ready real really reason receive recent
record records recover red redirect reduce refer reference refresh regex region register registry
reject related relay release releases reload rely remain remote remove rename render repeat replace
reply report reports request requests require required requires rescue research reset resolve
resource resources respond response responses rest restart restore restrict result results resume
retry return returns reveal reverse review rewrite rich right ring rise risk road role roles roll root
round route router routes row rows rule rules run runner running runs safe safer said sale same sample
sandbox save say says scale scan scanner schedule schema scheme scope score screen script scripts
scroll seal search second seconds secret secrets section secure security see seed seek seem seen
select self sell send sender sends sense sent separate sequence serial series serve server servers
service services session sessions set sets setting settings setup seven several shadow shall shape
share shared sharp sheet shell shield shift ship short should show shows shut side sign signal
signature signed simple since single site sites six size skip sleep slice slide slot slow small smart
snapshot socket sockets soft software solid solution some someone something soon sort sound source
sources space span spawn speak special specific speed spell spend spin split spot spread spring stack
staff stage stand standard star start started state statement states static station status statuses
stay steal step steps stick still stop storage store stores story stream streams strict string strings
strip strong structure studio study stuff style subject submit success such sudden suite sum summary
super supply support sure surface swap switch symbol sync syntax system systems tab table tables tag
tags take taken takes talk tap target targets task tasks team tell temp template templates ten term
terminal terms test tests text than that the their them theme then there these they thing things think
third this those though thought thread threads threat three through throw thus ticket tie time timeout
timer times tiny tip title today together token tokens too tool tools top topic total touch toward
trace track trade traffic trail train transfer transform transport trap trash travel tree trial trick
trigger trim trouble true trust try tunnel turn twice two type types under union unique unit units
unknown unless unlock until update updated updates upgrade upload upon upper url usage use used user
users uses using usual util utility utils valid validate validation value values variable variables
variant vary vault vector vendor verify version versions very via victim video view viewer views
virtual virus visit visual voice void volume wait walk wall want warn warning was watch water wave way
ways weak web week weeks weight well were what when where whether which while white who whole why wide
widget width wild will win window windows wire wise wish with within without word words work worker
workers workflow works world worm worse would wrap wrapper write writer writes wrong year years yes
yet you young your zero zone
`;

const EVERYDAY = new Set(WORDS.split(/\s+/).filter(Boolean));

/** Whether a package name is also a word that ordinary prose uses in its everyday sense. */
export function everydayWord(name: string): boolean {
  return EVERYDAY.has(name.trim().toLowerCase());
}
